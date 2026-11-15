"""Real loopback HTTP/application/Chromium; synthetic Root and model transport only.

No browser API interception, deployment configuration, remote SSH or real model is used.
"""

import json
import socket
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

import pytest
import test_defense_api as root_fixture
import uvicorn
from browser_defense_native_smoke import _open_transaction_receipt_history
from playwright.sync_api import Error, expect, sync_playwright
from test_defense_ai_api import provider
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark import ai_provider
from opsark.config import Settings
from opsark.defense_store import DefenseStore

TOKEN = "synthetic-real-browser-application-token-only"


@contextmanager
def serve(application):
    """Run the actual app only on a newly bound loopback socket."""
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
            timeout_graceful_shutdown=3,
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert thread.is_alive(), "Synthetic application stopped before readiness"
            if server.started:
                with opener.open(base + "/api/status", timeout=1) as response:
                    if response.status == 200:
                        break
            time.sleep(0.05)
        else:
            raise AssertionError("Synthetic application did not become ready")
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=3)
        listener.close()
        assert not thread.is_alive(), "Synthetic application did not stop"


@pytest.fixture
def assembled_browser_application(tmp_path, monkeypatch, target, main_module):
    # main_module's fixture clears all OPSARK_* and sets temporary DATA_DIR and
    # TOKEN before importing main, including its module-level default app.
    now = datetime.now(UTC)
    monkeypatch.setattr(root_fixture, "NOW", now)
    settings = Settings(
        data_dir=tmp_path / "synthetic-browser-application",
        token=TOKEN,
        ai_key="synthetic-browser-application-provider-token-only",
        ai_base_url="https://newfake-ai.example/v1",
        ai_model="newfake-http-model",
    )
    deployment = root_fixture.policy(
        target,
        ai={
            "enabled": True,
            "provider_fingerprint": ai_provider.provider_fingerprint(settings),
            "max_analyses_per_day": 2,
            "max_total_analyses": 2,
            "requires_ai": True,
        },
    )
    monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": target.host})
    monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": target})
    monkeypatch.setattr(main_module, "load_defense_policy", lambda _: deployment)
    app = main_module.create_app(settings)
    clock = [now]
    fake_root = root_fixture.FakeRoot(target, lambda: clock[0])
    service, ai = app.state.defense_service, app.state.defense_ai_service
    service.invoker = fake_root
    service.clock = lambda: clock[0]
    ai.now = lambda: clock[0]
    provider_calls = provider(monkeypatch)
    assert not app.state.patch_service.targets
    assert not settings.observation_enabled and not settings.vulnerability_scan_enabled
    with serve(app) as base, sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Error as error:
            pytest.skip("Playwright Chromium unavailable: " + type(error).__name__)
        context = browser.new_context()
        page = context.new_page()
        failures = []
        requests = []
        page.on("pageerror", lambda error: failures.append(type(error).__name__))
        page.on("request", lambda request: requests.append((request.method, request.url)))
        try:
            yield SimpleNamespace(
                app=app,
                page=page,
                base=base,
                root=fake_root,
                store=service.store,
                service=service,
                provider_calls=provider_calls,
                settings=settings,
                failures=failures,
                requests=requests,
            )
            assert not failures
            assert all(url.startswith(base + "/") for _, url in requests)
        finally:
            context.close()
            browser.close()


def login(h):
    h.page.goto(h.base)
    h.page.locator("#token-input").fill(TOKEN)
    h.page.locator("#login-form").evaluate("form => form.requestSubmit()")
    expect(h.page.locator("#app-shell")).to_be_visible()
    expect(h.page.locator("#automation-mode-select")).to_be_enabled()


def change_mode(h, mode):
    h.page.locator("#automation-mode-select").select_option(mode)
    with h.page.expect_response(
        lambda response: (
            urlsplit(response.url).path == "/api/automation" and response.request.method == "PUT"
        )
    ) as changed:
        h.page.locator("#save-automation-mode").click()
    assert changed.value.status == 200
    value = changed.value.json()
    assert value["mode"] == mode and value["mode_sync_complete"]
    assert value["sync_channels"] == ["ssh-defense"]
    assert value["execution_available"] is False
    expect(h.page.locator("#save-automation-mode")).to_be_disabled()
    return value["revision"]


def confirm(page):
    dialog = page.locator('[data-defense="dialog"]')
    expect(dialog).to_be_visible()
    dialog.locator('[data-defense="confirm"]').check()
    dialog.locator('[data-defense="send"]').click()
    expect(dialog).not_to_be_visible()


def response_for(page, suffix):
    return page.expect_response(
        lambda response: (
            response.request.method == "POST" and urlsplit(response.url).path.endswith(suffix)
        )
    )


def test_browser_actual_application_ai_and_original_transaction_reconciliation(
    assembled_browser_application,
):
    h = assembled_browser_application
    page = h.page
    login(h)
    revision = change_mode(h, "assisted")
    page.locator('button[data-view="security"]').click()
    arm = page.locator('[data-defense="arm"]')
    expect(arm).to_be_enabled()
    arm.click()
    with response_for(page, "/ssh-defense/arm") as armed:
        confirm(page)
    assert armed.value.status == 200
    cursor = armed.value.json()["request_id"]
    page.get_by_role("button", name="查询同一个原任务", exact=True).click()
    candidate = page.locator('[name="ssh-defense-source"]:enabled')
    expect(candidate).to_have_count(1)
    candidate.check()
    page.get_by_role("button", name="预览 AI 白名单摘要", exact=True).click()
    page.get_by_role("button", name="核对白名单并批准这次发送", exact=True).click()
    preview = page.locator('[data-defense="dialog-summary"]')
    expect(preview).to_contain_text('"candidate_alias": "candidate-1"')
    expect(preview).not_to_contain_text("192.0.2.10")
    with response_for(page, "/ai/analyses") as analyzed:
        confirm(page)
    assert analyzed.value.status == 200
    analysis = analyzed.value.json()
    assert analysis["status"] == "completed" and analysis["proof_sha256"]
    assert analysis["actions_executable"] is False
    expect(page.locator('[data-defense="ai"]')).to_contain_text("建议固定处置")
    with response_for(page, "/ssh-defense/prepare") as prepared:
        page.get_by_role("button", name="准备处置清单（不执行）", exact=True).click()
    assert prepared.value.status == 200
    action = prepared.value.json()
    rid, manifest = action["request_id"], action["manifest"]["sha256"]
    assert rid != cursor and action["mode_revision"] == revision
    assert action["current_result"]["state"] == "ready"
    execute = page.get_by_role("button", name="核对并执行这份清单", exact=True)
    execute.click()
    expect(preview).to_contain_text(rid)
    expect(preview).to_contain_text(manifest)
    h.root.lose = "apply"
    with response_for(page, f"/transactions/{rid}/apply") as lost:
        confirm(page)
    assert lost.value.status == 503
    expect(page.locator('[data-defense="detail"]')).to_contain_text("结果未确认，只查询原任务")
    expect(execute).to_be_disabled()
    assert sum(op == "apply" for op, _ in h.root.sent) == 1
    with response_for(page, f"/transactions/{rid}/query") as reconciled:
        page.get_by_role("button", name="查询同一个原任务", exact=True).click()
    assert reconciled.value.status == 200
    recovered = reconciled.value.json()
    assert recovered["request_id"] == rid and recovered["manifest"]["sha256"] == manifest
    assert recovered["current_result"]["state"] == "active"
    assert h.store.latched("fixture", h.service._context("fixture").defense_scope)
    page.get_by_role("button", name="核对并撤销原动作", exact=True).click()
    with response_for(page, f"/transactions/{rid}/revoke") as revoked:
        confirm(page)
    assert revoked.value.status == 200
    assert revoked.value.json()["current_result"]["state"] == "revoked"
    expect(page.locator('[data-defense="detail"]')).to_contain_text("最近确认已撤销")
    detail = page.locator('[data-defense="detail"]')
    expect(detail.locator("summary")).to_have_count(2)
    legacy = detail.locator("details.ssh-defense-legacy")
    expect(legacy.locator(":scope > summary")).to_have_text("早期工程复验记录 · 仅供历史查阅")
    receipts = _open_transaction_receipt_history(page)
    expect(receipts).to_contain_text("unavailable")
    expect(receipts).to_contain_text("query")
    assert legacy.evaluate("element => element.open") is False
    # Re-open the original action from persistent UI history, rather than relying
    # on a retained response object or silently creating a replacement task.
    history = page.locator('[data-defense="history"]')
    history.get_by_role("button").filter(has_text=cursor).click()
    history.get_by_role("button").filter(has_text=rid).click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text(manifest)
    reopened = DefenseStore(h.store.path)
    transactions = reopened.transactions("fixture")
    assert [row.rid for row in transactions if row.kind == "cursor"] == [cursor]
    assert [row.rid for row in transactions if row.kind == "action"] == [rid]
    records = reopened.observations(rid)
    assert any(row.state == "unavailable" and row.op == "apply" for row in records)
    assert any(row.state == "active" and row.op == "query" for row in records)
    assert any(row.state == "revoked" and row.op == "revoke" for row in records)
    assert sum(op == "arm" for op, _ in h.root.sent) == 1
    assert sum(op == "prepare" for op, _ in h.root.sent) == 1
    assert sum(op == "apply" for op, _ in h.root.sent) == 1
    assert sum(op == "revoke" for op, _ in h.root.sent) == 1
    assert len(h.provider_calls) == 1
    raw_provider = h.provider_calls[0].content.decode()
    for private in (cursor, rid, manifest, TOKEN, h.settings.ai_key, "192.0.2.10"):
        assert private not in raw_provider
    permit = reopened.ai_permit(analysis_id=analysis["analysis_id"])
    assert permit is not None
    assert reopened.usage(permit.intent_key).state == "consumed"
    assert json.loads(raw_provider)["model"] == "newfake-http-model"


def test_browser_actual_manual_mode_does_not_admit_prepare_or_execute(
    assembled_browser_application,
):
    h = assembled_browser_application
    page = h.page
    login(h)
    # A mode read is deliberately read-only. Persist and synchronize actual mode
    # changes through the UI, ending in manual, without granting any APT rights.
    change_mode(h, "assisted")
    change_mode(h, "manual")
    page.locator('button[data-view="security"]').click()
    arm = page.locator('[data-defense="arm"]')
    expect(arm).to_be_enabled()
    arm.click()
    with response_for(page, "/ssh-defense/arm") as armed:
        confirm(page)
    assert armed.value.status == 200
    page.get_by_role("button", name="查询同一个原任务", exact=True).click()
    page.locator('[name="ssh-defense-source"]:enabled').check()
    expect(page.get_by_role("button", name="准备处置清单（不执行）", exact=True)).to_be_disabled()
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)
    assert all(row.kind != "action" for row in h.store.transactions())
    assert not h.provider_calls and not h.app.state.patch_service.targets
