"""Read original session AI receipts in real main/Chromium with all senders off.

The caller supplies an isolated ten-database copy and expected public summaries.
This entry never clones data, locates credentials, or accepts an app factory.
Credentials stay file references on private stdin; only safe digests leave it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import defense_live_process as live  # noqa: E402
from defense_recheck_process_restart import (  # noqa: E402
    RestartAcceptanceError,
    _decode_settings,
    _json,
    _read,
    database_images,
    require,
)

from opsark.config import Settings  # noqa: E402

RECEIPT_KEYS = {
    "v",
    "session_ref",
    "analysis_id",
    "status",
    "decision",
    "usage_state",
    "input_digest",
    "proof_sha256",
    "actions_executable",
}
STATES = {"not_required", "not_started", "unknown", "completed", "refused", "failed", "stale"}
DECISIONS = {"propose_defense", "collect_more", "review_access", "no_action"}
QUOTA = {"reserved", "consumed", "unknown"}
STATUS_LABELS = {
    "not_required": "原策略不要求 AI，本次未调用",
    "not_started": "本次尚未登记 AI 调用",
    "unknown": "原分析结果未确认",
    "completed": "原分析已完成",
    "refused": "原分析未取得有效答复",
    "failed": "原分析失败",
    "stale": "原分析证据已失效",
}


def _sha(value):
    return hashlib.sha256(value.encode() if type(value) is str else value).hexdigest()


def _digest(value):
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _hex(value, size):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def _receipt(value, reference):
    require(
        type(value) is dict
        and set(value) == RECEIPT_KEYS
        and type(value["v"]) is int
        and value["v"] == 1
        and value["session_ref"] == reference
        and value["actions_executable"] is False
        and value["status"] in STATES,
        "receipt_schema_changed",
    )
    if value["status"] in {"not_required", "not_started"}:
        require(
            all(
                value[key] is None
                for key in (
                    "analysis_id",
                    "decision",
                    "usage_state",
                    "input_digest",
                    "proof_sha256",
                )
            ),
            "no_intent_receipt_changed",
        )
    else:
        require(
            _hex(value["analysis_id"], 32)
            and _hex(value["input_digest"], 64)
            and value["usage_state"] in QUOTA,
            "receipt_identity_changed",
        )
        if value["status"] == "completed":
            require(
                value["decision"] in DECISIONS
                and (
                    _hex(value["proof_sha256"], 64)
                    if value["decision"] == "propose_defense"
                    else value["proof_sha256"] is None
                ),
                "receipt_decision_changed",
            )
        else:
            require(
                value["decision"] is None and value["proof_sha256"] is None,
                "unconfirmed_receipt_promoted",
            )
    return value


@dataclass(frozen=True)
class ExpectedSession:
    host_id: str
    session_ref: str
    declaration_sha256: str
    phase: str
    receipt: dict

    def validate(self):
        require(
            type(self.host_id) is str
            and re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", self.host_id)
            and _hex(self.session_ref, 32)
            and _hex(self.declaration_sha256, 64)
            and self.phase in {"completed", "reconciliation_only", "stopped", "expired"},
            "invalid_expected_session",
        )
        _receipt(self.receipt, self.session_ref)
        return self


def _configuration(settings):
    # Keep the original helper's strict rejection of session=true and all AI.
    document = live._configuration(settings)
    require(
        settings.defense_session_enabled is False
        and settings.patch_inventory_path is None
        and settings.defense_task_watch_enabled is False
        and settings.vulnerability_scan_enabled is False
        and settings.observation_enabled is False
        and settings.web_observation_enabled is False,
        "history_senders_must_be_disabled",
    )
    return document


class ReceiptHistoryProcess(live.LiveProcess):
    def _command(self):
        return [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--receipt-history-child",
        ]

    def _finish(self, success):
        super()._finish(success)
        if success:
            require(
                all(
                    self.audit.get(key) == 0
                    for key in ("ssh_attempts", "model_attempts", "blocked_writes")
                )
                and self.audit.get("session_disabled") is True
                and self.audit.get("session_worker_stopped") is True
                and self.audit.get("production_root_invoker") is True
                and self.audit.get("production_business_collector") is True,
                "history_process_boundary_failed",
            )


def _get(process, settings, path):
    status, raw, headers = _read(process.base, settings.token, path)
    require(status == 200, "history_read_unavailable")
    return json.loads(raw), headers


def _browser_observe(process, settings, expected):
    from playwright.sync_api import expect, sync_playwright

    rows, requests, denied, errors = [], [], [], []
    base = urlsplit(process.base)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()

        def readonly(route):
            request, endpoint = route.request, urlsplit(route.request.url)
            if (endpoint.scheme, endpoint.hostname, endpoint.port) != (
                base.scheme,
                base.hostname,
                base.port,
            ) or request.method not in {"GET", "HEAD"}:
                denied.append(True)
                route.abort()
            else:
                route.continue_()

        context.route("**/*", readonly)
        page = context.new_page()
        page.on("request", lambda request: requests.append(request.method))
        page.on("pageerror", lambda _error: errors.append(True))
        try:
            page.goto(process.base)
            page.locator("#token-input").fill(settings.token)
            page.locator("#login-form").evaluate("form => form.requestSubmit()")
            expect(page.locator("#app-shell")).to_be_visible()
            page.locator('button[data-view="security"]').click()
            host_select = page.locator('[data-defense="host"]')
            for item in expected:
                if host_select.input_value() != item.host_id:
                    host_select.select_option(item.host_id)
                section = page.get_by_role("region", name="单次防护会话", exact=True)
                card = section.locator("button.ssh-defense-row").filter(has_text=item.session_ref)
                expect(card).to_have_count(1)
                path = "/api/hosts/" + item.host_id + "/ssh-defense/sessions/" + item.session_ref
                with page.expect_response(
                    lambda response, url=path: (
                        response.request.method == "GET" and response.url.endswith(url)
                    )
                ) as selected:
                    card.click()
                require(selected.value.status == 200, "history_card_unavailable")
                record = selected.value.json()
                require(
                    record["session_ref"] == item.session_ref
                    and record["declaration_sha256"] == item.declaration_sha256
                    and record["phase"] == item.phase
                    and record["owned_by_current_boot"] is False
                    and record["can_stop"] is False
                    and record["requires_ai"] is (item.receipt["status"] != "not_required")
                    and record["business_verdict"] == "pending",
                    "old_owner_history_changed",
                )
                expect(
                    section.get_by_role("button", name="核对并停止原会话", exact=True)
                ).to_have_count(0)
                expect(
                    section.get_by_role("button", name="启动这一次防护会话", exact=True)
                ).to_be_disabled()
                with page.expect_response(
                    lambda response, url=path + "/ai-receipt": (
                        response.request.method == "GET" and response.url.endswith(url)
                    )
                ) as received:
                    section.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
                require(received.value.status == 200, "history_receipt_unavailable")
                actual = _receipt(received.value.json(), item.session_ref)
                require(actual == item.receipt, "original_receipt_changed")
                receipt_section = section.get_by_role("region", name="原 AI 安全回执", exact=True)
                expect(receipt_section).to_contain_text(STATUS_LABELS[actual["status"]])
                expect(receipt_section).to_contain_text("不是提供方账单回执")
                for value in (
                    actual["analysis_id"],
                    actual["input_digest"],
                    actual["proof_sha256"],
                ):
                    if value is not None:
                        expect(receipt_section).to_contain_text(value)
                rows.append(
                    {
                        "host_sha256": _sha(item.host_id),
                        "session_ref_sha256": _sha(item.session_ref),
                        "declaration_sha256": item.declaration_sha256,
                        "phase": item.phase,
                        "receipt_sha256": _digest(actual),
                        "status": actual["status"],
                        "decision": actual["decision"],
                        "usage_state": actual["usage_state"],
                        "business_verdict": "pending",
                        "actions_executable": False,
                    }
                )
            require(
                not errors and not denied and all(method in {"GET", "HEAD"} for method in requests),
                "browser_readonly_boundary_failed",
            )
        finally:
            context.close()
            browser.close()
    return rows, len(requests)


def run_receipt_history(
    settings: Settings, expected: tuple[ExpectedSession, ...], *, proof_path: Path
):
    """Observe only the caller's isolated copy. Never locate or clone a source."""
    _configuration(settings)
    require(
        type(expected) is tuple
        and 1 <= len(expected) <= 6
        and all(type(item) is ExpectedSession for item in expected),
        "invalid_history_expectations",
    )
    for item in expected:
        item.validate()
    require(
        len({(item.host_id, item.session_ref) for item in expected}) == len(expected),
        "duplicate_history_expectation",
    )
    require(
        settings.data_dir.is_absolute()
        and settings.data_dir.is_dir()
        and not settings.data_dir.is_symlink()
        and not settings.data_dir.is_junction(),
        "isolated_copy_required",
    )
    require(
        proof_path.is_absolute()
        and proof_path.parent.is_dir()
        and not proof_path.exists()
        and not proof_path.parent.is_relative_to(settings.data_dir),
        "proof_not_fresh",
    )
    before = database_images(settings.data_dir)
    directory = proof_path.parent / (proof_path.stem + "-processes")
    require(not directory.exists(), "history_process_directory_exists")
    directory.mkdir(mode=0o700)
    proof = {
        "schema": "opsark-session-receipt-history-browser/v1",
        "completed": False,
        "browser_verified": False,
        "ssh_attempts": None,
        "model_attempts": None,
        "blocked_writes": None,
        "resident_modified": False,
        "business_recollection": False,
    }
    process = ReceiptHistoryProcess(settings, directory, 1)
    try:
        with process:
            status, _ = _get(process, settings, "/api/ssh-defense/sessions/status")
            require(
                status["enabled"] is False
                and status["running"] is False
                and status["owned_sessions"] == 0,
                "history_sender_enabled",
            )
            rows, request_count = _browser_observe(process, settings, expected)
        require(database_images(settings.data_dir) == before, "ten_database_images_changed")
        proof.update(
            completed=True,
            browser_verified=True,
            session_count=len(rows),
            process_count=1,
            read_requests=process.audit["read_requests"],
            browser_request_count=request_count,
            blocked_writes=process.audit["blocked_writes"],
            ssh_attempts=process.audit["ssh_attempts"],
            model_attempts=process.audit["model_attempts"],
            production_root_invoker=process.audit["production_root_invoker"],
            production_business_collector=process.audit["production_business_collector"],
            session_disabled=True,
            old_owner_readonly_verified=True,
            stores_unchanged=True,
            fees_unchanged=True,
            rows=rows,
            ten_database_images_sha256=_digest(before),
            business_verdict="pending",
        )
    except Exception:
        proof["failure_code"] = "receipt_history_unconfirmed"
        for key in ("ssh_attempts", "model_attempts", "blocked_writes"):
            actual = process.audit.get(key)
            if type(actual) is int and actual >= 0:
                proof[key] = actual
    _json(proof_path, proof)
    return proof


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
        "ssh_attempts": 0,
        "model_attempts": 0,
        "blocked_writes": 0,
        "read_requests": 0,
    }
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    settings = _decode_settings(payload["settings"])
    _configuration(settings)
    os.environ["OPSARK_DATA_DIR"] = str(ready.parent / ("bootstrap-" + str(os.getpid())))
    os.environ["OPSARK_TOKEN"] = settings.token
    import httpx
    import paramiko
    import uvicorn
    from starlette.responses import Response

    def no_ssh(*_args, **_kwargs):
        counts["ssh_attempts"] += 1
        raise RestartAcceptanceError("ssh_forbidden")

    def no_model(*_args, **_kwargs):
        counts["model_attempts"] += 1
        raise RestartAcceptanceError("model_forbidden")

    async def no_async_model(*args, **kwargs):
        return no_model(*args, **kwargs)

    paramiko.SSHClient.connect = no_ssh
    httpx.HTTPTransport.handle_request = no_model
    httpx.AsyncHTTPTransport.handle_async_request = no_async_model
    try:
        from opsark.business_readiness import run_business_readiness
        from opsark.defense_client import invoke
        from opsark.main import create_app

        app = create_app(settings)
        worker = app.state.defense_session_worker
        counts.update(
            production_root_invoker=app.state.defense_service.invoker is invoke,
            production_business_collector=app.state.defense_recheck_service.collector
            is run_business_readiness,
            worker_disabled=not settings.defense_worker_enabled,
            session_disabled=not worker.enabled,
        )

        @app.middleware("http")
        async def readonly(request, call_next):
            if request.method not in {"GET", "HEAD"}:
                counts["blocked_writes"] += 1
                return Response(status_code=405)
            counts["read_requests"] += 1
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
            deadline = time.monotonic() + 90
            while not server.started:
                if stop.exists() or time.monotonic() >= deadline:
                    server.should_exit = True
                    return
                time.sleep(0.02)
            _json(ready, {"pid": os.getpid(), "base": f"http://127.0.0.1:{port}"})
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
        require(not supervisor.is_alive(), "history_supervisor_not_stopped")
        counts["stopped"] = True
        counts["session_worker_stopped"] = (
            worker.stopped.is_set() and not worker.status()["running"]
        )
        _json(audit, counts)
        return 0
    except Exception:
        counts["failure_code"] = "history_child_unconfirmed"
        _json(audit, counts)
        return 1


if __name__ == "__main__":
    require(sys.argv[1:] == ["--receipt-history-child"], "invalid_history_child_entry")
    raise SystemExit(_child())
