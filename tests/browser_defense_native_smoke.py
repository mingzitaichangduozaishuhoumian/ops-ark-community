"""Administrator-run real browser/SSH/provider acceptance in a fresh private lab.

This module does not select a server, execute an administrator command, or provision
an identity. Its three native callbacks must be supplied by the scoped lab adapter.
Provider credentials remain a file reference; proofs contain bounded metadata only.
"""

import importlib
import json
import os
import re
import secrets
import socket
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

import httpx
import uvicorn
from playwright.sync_api import expect, sync_playwright

from opsark import ai_provider
from opsark.ai_egress import MODEL
from opsark.config import Settings, validate_ai_url
from opsark.defense_ai import ModelInput, request_body
from opsark.defense_client import _read_file
from opsark.defense_models import canonical, digest
from opsark.defense_store import DefenseStore

DATABASES = (
    "reports.sqlite3",
    "baselines.sqlite3",
    "security.sqlite3",
    "web-security.sqlite3",
    "security-ai.sqlite3",
    "automation.sqlite3",
    "patches.sqlite3",
    "vulnerability-ai.sqlite3",
    "automatic.sqlite3",
    "vulnerability-watch.sqlite3",
)
_observer_lock = threading.Lock()


class NativeBrowserError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__("Native browser acceptance did not confirm this phase.")


class _AcceptanceStopped(Exception):
    """An explicit non-positive result whose contexts still need orderly shutdown."""


def require(condition, code):
    if not condition:
        raise NativeBrowserError(code)


def _unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "provider_configuration_invalid")
        result[name] = value
    return result


def _nonfinite(_value):
    raise NativeBrowserError("provider_configuration_invalid")


def load_existing_provider_settings(
    data_dir: Path,
    token: str,
    inventory_path: Path,
    defense_inventory_path: Path,
    defense_policy_path: Path,
) -> Settings:
    """Opaque bounded loading of the two previously authorized provider references."""
    try:
        config_path = Path(os.environ["OPSARK_NATIVE_SMOKE_PROVIDER_CONFIG"])
        key_path = Path(os.environ["OPSARK_NATIVE_SMOKE_PROVIDER_KEY"])
        require(
            config_path.is_absolute() and key_path.is_absolute(), "provider_configuration_invalid"
        )
        raw, seal = _read_file(config_path, 16384, private=False)
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
        require(
            type(value) is dict
            and {"base_url", "model"} <= set(value)
            and not set(value)
            - {
                "base_url",
                "model",
                "response_format",
                "token_limit_parameter",
                "max_output_tokens",
                "thinking_mode",
            },
            "provider_configuration_invalid",
        )
        require(
            type(value["base_url"]) is str
            and type(value["model"]) is str
            and MODEL.fullmatch(value["model"]) is not None,
            "provider_configuration_invalid",
        )
        settings = Settings(
            data_dir=data_dir,
            token=token,
            inventory_path=inventory_path,
            defense_inventory_path=defense_inventory_path,
            defense_policy_path=defense_policy_path,
            ai_base_url=validate_ai_url(value["base_url"]),
            ai_model=value["model"],
            ai_key_file=key_path,
            ai_response_format=value.get("response_format", "json_object"),
            ai_token_limit_parameter=value.get("token_limit_parameter", "max_tokens"),
            ai_max_output_tokens=value.get("max_output_tokens", 2048),
            ai_thinking_mode=value.get("thinking_mode", "provider_default"),
        )
        _, current = _read_file(config_path, 16384, private=False)
        require(current == seal, "provider_configuration_changed")
        return settings
    except Exception:
        raise NativeBrowserError("provider_configuration_invalid") from None


class ProviderObserver:
    """Observe and bound real sends without replacing the transport or response."""

    def __init__(self, settings):
        self.settings = settings
        self.expected = None
        self.forbidden = {settings.token, "127.0.0.1", "198.18.241."}
        if settings.ai_key:
            self.forbidden.add(settings.ai_key)
        self.entries = self.dispatches = self.responses = 0
        self.request_sha256 = None
        self.status_code = None
        self.elapsed_ms = None
        self._lock = threading.Lock()

    def arm(self, summary, references=()):
        self.expected = ModelInput.model_validate_json(canonical(summary)).model_dump(mode="json")
        self.forbidden.update(reference for reference in references if type(reference) is str)

    def validate(self, request):
        if self.expected is None:
            raise NativeBrowserError("provider_unplanned_request")
        try:
            document = json.loads(
                request.content, object_pairs_hook=_unique, parse_constant=_nonfinite
            )
            expected = request_body(self.expected, self.settings)
            expected[self.settings.ai_token_limit_parameter] = self.settings.ai_max_output_tokens
            if self.settings.ai_thinking_mode != "provider_default":
                expected["thinking"] = {"type": self.settings.ai_thinking_mode}
            require(document == expected, "provider_projection_changed")
            require(request.method == "POST", "provider_projection_changed")
            # This observes only the JSON body. Credentials in transport headers
            # are never read, recorded, inspected or copied by this observer.
            encoded = canonical(document)
            require(
                not any(item and item.encode() in encoded for item in self.forbidden),
                "provider_private_reference_blocked",
            )
            return digest(document)
        except NativeBrowserError:
            raise
        except Exception:
            raise NativeBrowserError("provider_projection_changed") from None

    @contextmanager
    def installed(self):
        require(_observer_lock.acquire(blocking=False), "provider_observer_already_active")
        original = httpx.AsyncClient.send

        async def observed(client, request, *args, **kwargs):
            with self._lock:
                self.entries += 1
                require(self.entries == 1, "provider_extra_attempt_blocked")
                self.request_sha256 = self.validate(request)
                self.dispatches += 1
            started = time.monotonic()
            try:
                response = await original(client, request, *args, **kwargs)
                self.responses += 1
                self.status_code = response.status_code
                return response
            finally:
                self.elapsed_ms = round((time.monotonic() - started) * 1000)

        httpx.AsyncClient.send = observed
        try:
            yield self
        finally:
            httpx.AsyncClient.send = original
            _observer_lock.release()

    def safe(self):
        return {
            "client_send_entries": self.entries,
            "transport_dispatches": self.dispatches,
            "http_response_headers_received": self.responses,
            "response_status_code": self.status_code,
            "request_body_sha256": self.request_sha256,
            "request_start_to_headers_or_error_ms": self.elapsed_ms,
            "provider_fingerprint": ai_provider.provider_fingerprint(self.settings),
        }


@contextmanager
def _environment(data_dir, token):
    names = {"OPSARK_DATA_DIR", "OPSARK_TOKEN"} | {
        name for name in os.environ if name.startswith("OPSARK_")
    }
    saved = {name: os.environ.get(name) for name in names}
    bootstrap = data_dir.parent / ("bootstrap-" + secrets.token_hex(8))
    try:
        for name in names:
            os.environ.pop(name, None)
        os.environ["OPSARK_DATA_DIR"] = str(bootstrap)
        os.environ["OPSARK_TOKEN"] = token
        yield importlib.import_module("opsark.main").create_app
    finally:
        for name in names:
            previous = saved[name]
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


@contextmanager
def _serve(application):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=port,
            loop="asyncio",
            http="h11",
            ws="none",
            access_log=False,
            log_level="error",
            timeout_graceful_shutdown=2,
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            require(thread.is_alive() and time.monotonic() < deadline, "application_start_failed")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=4)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=2)
        listener.close()
        require(not thread.is_alive(), "application_stop_failed")


def _snapshot(callback):
    value = callback()
    allowed = {
        "usage_count",
        "intents",
        "kernel_active",
        "records",
        "ledger_sha256",
        "candidate_failure_events",
        "candidate_success_events",
    }
    require(type(value) is dict and not set(value) - allowed, "native_snapshot_invalid")
    require({"usage_count", "intents", "kernel_active"} <= set(value), "native_snapshot_invalid")
    require(type(value["kernel_active"]) is bool, "native_snapshot_invalid")
    for name in ("usage_count", "intents", "candidate_failure_events", "candidate_success_events"):
        if name in value:
            require(
                type(value[name]) is int and 0 <= value[name] <= 2**31 - 1,
                "native_snapshot_invalid",
            )
    if "records" in value:
        require(
            type(value["records"]) is dict
            and not set(value["records"]) - {"mode", "cursor", "action"}
            and all(type(n) is int and 0 <= n <= 128 for n in value["records"].values()),
            "native_snapshot_invalid",
        )
    if "ledger_sha256" in value:
        require(_hex(value["ledger_sha256"], 64), "native_snapshot_invalid")
    return value


def _health(callback):
    value = callback()
    names = {"management_ssh_ok", "contrast_ssh_ok", "same_source_http_ok"}
    require(
        type(value) is dict
        and set(value) == names
        and all(item is True for item in value.values()),
        "native_health_not_confirmed",
    )
    return value


def _hex(value, count):
    return (
        type(value) is str and len(value) == count and all(c in "0123456789abcdef" for c in value)
    )


def _response(page, suffix, *, method="POST"):
    return page.expect_response(
        lambda response: (
            response.request.method == method and response.url.split("?", 1)[0].endswith(suffix)
        ),
        timeout=40000,
    )


def _confirm(page):
    dialog = page.locator('[data-defense="dialog"]')
    expect(dialog).to_be_visible()
    dialog.locator('[data-defense="confirm"]').check()
    dialog.locator('[data-defense="send"]').click()
    expect(dialog).not_to_be_visible()


def _open_transaction_receipt_history(page):
    """Open the original transaction's receipts, separately from legacy rechecks."""
    history = page.locator('[data-defense="detail"] details.ssh-defense-history-detail')
    expect(history).to_have_count(1)
    summary = history.locator(":scope > summary")
    expect(summary).to_have_count(1)
    expect(summary).to_have_text(re.compile(r"^历史回执 · [0-9]+ 条$"))
    if not history.evaluate("element => element.open"):
        summary.click()
    receipts = history.locator("ol.ssh-defense-receipts")
    expect(receipts).to_be_visible()
    return receipts


def _login(browser, base, token):
    context = browser.new_context()
    page = context.new_page()
    page.set_default_timeout(35000)
    errors = []
    page.on("pageerror", lambda _error: errors.append(True))
    page.goto(base)
    page.locator("#token-input").fill(token)
    page.locator("#login-form").evaluate("form => form.requestSubmit()")
    expect(page.locator("#app-shell")).to_be_visible()
    expect(page.locator("#automation-mode-select")).to_be_enabled()
    return context, page, errors


def _write_proof(path, record):
    require(path.is_absolute() and path.parent.is_dir() and not path.exists(), "proof_path_invalid")
    raw = json.dumps(record, sort_keys=True, indent=2, allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= 65536, "proof_budget_exceeded")
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        raise NativeBrowserError("proof_write_failed") from None


def _check_application(app, settings):
    service = app.state.defense_service
    require(
        len(service.targets) == 1 and not app.state.patch_service.targets,
        "application_scope_invalid",
    )
    require(
        all(target.host.public.address == "127.0.0.1" for target in service.targets.values())
        and service.policy.enabled
        and service.policy.ai.enabled
        and service.policy.ai.requires_ai
        and service.policy.ai.max_analyses_per_day == service.policy.ai.max_total_analyses == 1
        and service.policy.ai.provider_fingerprint == ai_provider.provider_fingerprint(settings),
        "application_scope_invalid",
    )
    grant = service.policy.execution
    require(
        grant is not None and grant.max_actions_per_day == grant.max_total_actions == 1,
        "application_scope_invalid",
    )
    return service


def run_native_browser(
    settings: Settings,
    *,
    stimulate_after_arm: Callable,
    snapshot: Callable,
    health: Callable,
    proof_path: Path,
) -> dict:
    """Run one explicit browser action; native/provider refusals never trigger retry.

    Callbacks return bounded metadata. ``stimulate_after_arm(cursor_rid)`` must
    create only the five controlled failed authentications; health must never
    perform a candidate SSH login inside the observation window.
    """
    require(isinstance(settings, Settings), "settings_invalid")
    require(
        settings.data_dir.is_absolute()
        and settings.data_dir.resolve() == settings.data_dir
        and settings.data_dir.parent.is_dir()
        and not settings.data_dir.is_symlink()
        and not any((settings.data_dir / name).exists() for name in DATABASES)
        and len(settings.token) >= 32
        and settings.ai_provider == "openai"
        and not settings.observation_enabled
        and not settings.web_observation_enabled
        and not settings.vulnerability_scan_enabled
        and not settings.defense_worker_enabled,
        "settings_scope_invalid",
    )
    require(
        settings.patch_inventory_path is None
        and settings.automation_policy_path is None
        and settings.vulnerability_webhook_url is None
        and settings.vulnerability_webhook_key_file is None,
        "settings_scope_invalid",
    )
    require(
        all(callable(f) for f in (stimulate_after_arm, snapshot, health)),
        "native_callbacks_invalid",
    )
    require(proof_path.is_absolute() and not proof_path.exists(), "proof_path_invalid")
    record = {
        "schema": "opsark-native-defense-browser/v1",
        "completed": False,
        "phase": "starting",
        "root_and_provider_replaced": False,
        "same_python_new_application_instances": 0,
        "host_or_python_process_restart_verified": False,
        "resident_modified": False,
    }
    observer = ProviderObserver(settings)
    app = None
    try:
        record["native_before"] = _snapshot(snapshot)
        require(
            record["native_before"]["usage_count"] == record["native_before"]["intents"] == 0
            and not record["native_before"]["kernel_active"],
            "native_scope_not_fresh",
        )
        with _environment(settings.data_dir, settings.token) as create_app, observer.installed():
            app = create_app(settings)
            service = _check_application(app, settings)
            for target in service.targets.values():
                observer.forbidden.update(
                    (target.root_scope_sha256, target.boot_ref, target.binding_ref)
                )
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    with _serve(app) as base:
                        record["same_python_new_application_instances"] = 1
                        context, page, errors = _login(browser, base, settings.token)
                        try:
                            record["phase"] = "mode_sync"
                            page.locator("#automation-mode-select").select_option("assisted")
                            with _response(page, "/api/automation", method="PUT") as changed:
                                page.locator("#save-automation-mode").click()
                            mode = changed.value.json()
                            require(
                                changed.value.status == 200
                                and mode["mode"] == "assisted"
                                and mode["mode_sync_complete"]
                                and mode["sync_channels"] == ["ssh-defense"]
                                and mode["execution_available"] is False,
                                "mode_sync_not_confirmed",
                            )
                            revision = mode["revision"]
                            record["mode_revision"] = revision
                            page.locator('button[data-view="security"]').click()
                            arm = page.locator('[data-defense="arm"]')
                            expect(arm).to_be_enabled()
                            arm.click()
                            with _response(page, "/ssh-defense/arm") as armed:
                                _confirm(page)
                            require(armed.value.status == 200, "observation_not_confirmed")
                            cursor = armed.value.json()["request_id"]
                            require(_hex(cursor, 32), "observation_not_confirmed")
                            record["cursor_request_id"] = cursor
                            observer.forbidden.add(cursor)
                            record["phase"] = "controlled_authentication"
                            stimulus = stimulate_after_arm(cursor)
                            require(type(stimulus) is dict, "native_stimulus_not_confirmed")
                            with _response(page, f"/transactions/{cursor}/query") as observed:
                                page.get_by_role(
                                    "button", name="查询同一个原任务", exact=True
                                ).click()
                            require(observed.value.status == 200, "candidate_not_confirmed")
                            candidates = observed.value.json()["current_result"]["candidates"]
                            eligible = [c for c in candidates if c["classification"] == "eligible"]
                            require(len(eligible) == 1, "candidate_not_confirmed")
                            candidate = eligible[0]
                            require(
                                candidate["distinct_failure_ports"] >= 5, "candidate_not_confirmed"
                            )
                            observer.forbidden.update(
                                (candidate["source_ref"], candidate["evidence_sha256"])
                            )
                            page.locator('[name="ssh-defense-source"]:enabled').check()
                            with _response(page, "/ai/preview", method="GET") as previewed:
                                page.get_by_role(
                                    "button", name="预览 AI 白名单摘要", exact=True
                                ).click()
                            require(previewed.value.status == 200, "ai_preview_not_confirmed")
                            preview = previewed.value.json()
                            observer.arm(preview["input"])
                            record["phase"] = "ai_analysis"
                            page.get_by_role(
                                "button", name="核对白名单并批准这次发送", exact=True
                            ).click()
                            with _response(page, "/ai/analyses") as analyzed:
                                _confirm(page)
                            require(analyzed.value.status == 200, "ai_analysis_not_confirmed")
                            analysis = analyzed.value.json()
                            record["analysis_id"] = analysis["analysis_id"]
                            record["ai_status"] = analysis["status"]
                            record["ai_decision"] = analysis["decision"]
                            require(
                                observer.entries == observer.dispatches == 1,
                                "provider_count_not_one",
                            )
                            if not (
                                analysis["status"] == "completed"
                                and analysis["decision"] == "propose_defense"
                                and _hex(analysis["proof_sha256"], 64)
                            ):
                                record["phase"] = "ai_did_not_authorize_proposal"
                                record["native_after"] = _snapshot(snapshot)
                                require(
                                    record["native_after"]["usage_count"]
                                    == record["native_after"]["intents"]
                                    == 0
                                    and not record["native_after"]["kernel_active"]
                                    and not any(
                                        t.kind == "action" for t in service.store.transactions()
                                    ),
                                    "unexpected_native_action",
                                )
                                raise _AcceptanceStopped
                            record["phase"] = "prepare"
                            with _response(page, "/ssh-defense/prepare") as prepared:
                                page.get_by_role(
                                    "button", name="准备处置清单（不执行）", exact=True
                                ).click()
                            require(prepared.value.status == 200, "prepare_not_confirmed")
                            action = prepared.value.json()
                            rid, manifest = action["request_id"], action["manifest"]["sha256"]
                            require(
                                _hex(rid, 32) and rid != cursor and _hex(manifest, 64),
                                "prepare_not_confirmed",
                            )
                            record.update(request_id=rid, manifest_sha256=manifest)
                            record["health_before_apply"] = _health(health)
                            record["phase"] = "apply_unknown"
                            page.get_by_role(
                                "button", name="核对并执行这份清单", exact=True
                            ).click()
                            with _response(page, f"/transactions/{rid}/apply") as lost:
                                _confirm(page)
                            require(lost.value.status == 503, "apply_receipt_loss_not_observed")
                            expect(page.locator('[data-defense="detail"]')).to_contain_text(
                                "结果未确认，只查询原任务"
                            )
                            record["apply_unknown_before_restart"] = True
                            require(not errors, "browser_script_failed")
                        finally:
                            context.close()
                    require(
                        app.state.defense_service.stopped.is_set(), "first_application_not_stopped"
                    )
                    record["first_application_lifespan_stopped"] = True
                    app = create_app(settings)
                    service = _check_application(app, settings)
                    with _serve(app) as base:
                        record["same_python_new_application_instances"] = 2
                        context, page, errors = _login(browser, base, settings.token)
                        try:
                            record["phase"] = "original_task_reconciliation"
                            page.locator('button[data-view="security"]').click()
                            history = page.locator('[data-defense="history"]')
                            history.get_by_role("button").filter(has_text=rid).click()
                            expect(page.locator('[data-defense="detail"]')).to_contain_text(
                                manifest
                            )
                            with _response(page, f"/transactions/{rid}/query") as reconciled:
                                page.get_by_role(
                                    "button", name="查询同一个原任务", exact=True
                                ).click()
                            require(reconciled.value.status == 200, "reconciliation_not_confirmed")
                            current = reconciled.value.json()
                            require(
                                current["request_id"] == rid
                                and current["manifest"]["sha256"] == manifest,
                                "original_task_binding_changed",
                            )
                            record["reconciled_state"] = (
                                current["current_result"]["state"]
                                if current["current_result"]
                                else "unknown"
                            )
                            if record["reconciled_state"] != "active":
                                record["phase"] = "active_receipt_pending_acceptance"
                                record["native_after"] = _snapshot(snapshot)
                                raise _AcceptanceStopped
                            record["reconciled_original_task_after_application_restart"] = True
                            record["phase"] = "revoke"
                            page.get_by_role("button", name="核对并撤销原动作", exact=True).click()
                            with _response(page, f"/transactions/{rid}/revoke") as revoked:
                                _confirm(page)
                            require(
                                revoked.value.status == 200
                                and revoked.value.json()["current_result"]["state"] == "revoked",
                                "revoke_not_confirmed",
                            )
                            receipts = _open_transaction_receipt_history(page)
                            expect(receipts).to_contain_text("unavailable")
                            history.get_by_role("button").filter(has_text=cursor).click()
                            history.get_by_role("button").filter(has_text=rid).click()
                            expect(page.locator('[data-defense="detail"]')).to_contain_text(
                                manifest
                            )
                            record["old_history_reopened_after_application_restart"] = True
                            require(not errors, "browser_script_failed")
                            record["native_after"] = _snapshot(snapshot)
                            require(
                                record["native_after"]["usage_count"]
                                == record["native_after"]["intents"]
                                == 1
                                and not record["native_after"]["kernel_active"],
                                "native_final_state_not_confirmed",
                            )
                            record["health_after_revoke"] = _health(health)
                            record["completed"] = True
                            record["phase"] = "verified"
                        finally:
                            context.close()
                finally:
                    browser.close()
    except _AcceptanceStopped:
        pass
    except NativeBrowserError as error:
        record["failure_code"] = error.code
    except Exception as error:
        record["failure_code"] = "acceptance_phase_not_confirmed"
        record["failure_kind"] = (
            type(error).__name__
            if type(error).__name__
            in {
                "TimeoutError",
                "AssertionError",
                "KeyError",
                "TypeError",
                "AttributeError",
                "ValueError",
                "Error",
            }
            else "Exception"
        )
    if "native_after" not in record:
        try:
            record["native_after"] = _snapshot(snapshot)
        except Exception:
            record["native_final_evidence_unavailable"] = True
            record["completed"] = False
    return _finish(proof_path, record, observer, app)


def _finish(proof_path, record, observer, app):
    record["provider"] = observer.safe()
    if app is not None:
        record["final_application_lifespan_stopped"] = app.state.defense_service.stopped.is_set()
        store = DefenseStore(app.state.defense_store.path)
        transactions = store.transactions()
        record["local_transaction_counts"] = {
            kind: sum(t.kind == kind for t in transactions) for kind in ("mode", "cursor", "action")
        }
        if "analysis_id" in record:
            permit = store.ai_permit(analysis_id=record["analysis_id"])
            if permit is not None:
                record["ai_usage_state"] = store.usage(permit.intent_key).state
        if "request_id" in record:
            rows = store.observations(record["request_id"])
            record["apply_unknown_history_retained"] = any(
                r.op == "apply" and r.state == "unavailable" for r in rows
            )
            record["active_query_history_retained"] = any(
                r.op == "query" and r.state == "active" for r in rows
            )
            transaction = store.transaction(record["request_id"])
            record["unknown_latch_retained"] = store.latched(
                transaction.context.host_id, transaction.context.defense_scope
            )
            if record["completed"]:
                confirmed = (
                    record["local_transaction_counts"]["cursor"]
                    == record["local_transaction_counts"]["action"]
                    == 1
                    and record["apply_unknown_history_retained"]
                    and record["active_query_history_retained"]
                    and record["unknown_latch_retained"]
                    and record.get("ai_usage_state") == "consumed"
                    and observer.entries == observer.dispatches == observer.responses == 1
                    and record["final_application_lifespan_stopped"]
                )
                if not confirmed:
                    record["completed"] = False
                    record["failure_code"] = "local_final_state_not_confirmed"
    _write_proof(proof_path, record)
    return record
