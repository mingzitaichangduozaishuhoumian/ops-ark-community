"""Real browser/DOM checks with synthetic API traffic only; no model or SSH calls."""

import copy
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Error, expect, sync_playwright

from opsark.defense_ai import ModelCandidate, ModelInput
from opsark.defense_models import POLICY_SHA256, DefenseReply
from opsark.defense_store import (
    ConfirmedMetadata,
    DefenseContext,
    ModeAckMetadata,
    ObservationMetadata,
)

ROOT = Path(__file__).resolve().parents[1]
CURSOR, ACTION, SOURCE, ANALYSIS = (f"{number:032x}" for number in range(1, 5))
TOKEN = "synthetic-defense-browser-token-only"
UNTRUSTED = '<img src=x onerror="window.defenseInjected=true">'


def stamp(seconds=0):
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def transaction(kind, state, *, mode="semi"):
    rid = CURSOR if kind == "cursor" else ACTION
    reply = {
        "v": 1,
        "op": {"armed": "arm", "attached": "query", "ready": "prepare"}.get(state, state),
        "request_id": rid,
        "scope_sha256": "1" * 64,
        "policy_sha256": POLICY_SHA256,
        "boot_ref": "2" * 64,
        "binding_ref": "3" * 64,
        "mode": mode,
        "mode_revision": 4,
        "state": state,
        "action_id": None if kind == "cursor" else "6" * 32,
        "cursor_id": "7" * 32,
        "manifest_sha256": None if kind == "cursor" else "d" * 64,
        "deadline_at": stamp(110),
        "remaining_ms": 59000 if state == "active" else None,
        "reason_code": "ok",
        "candidates": [],
    }
    if state in {"active", "revoked"}:
        reply["op"] = "apply" if state == "active" else "revoke"
    if kind == "cursor" and state == "attached":
        reply["candidates"] = [
            {
                "source_ref": SOURCE,
                "source_alias": "fixture-a",
                "classification": "eligible",
                "distinct_failure_ports": 5,
                "evidence_sha256": "e" * 64,
            }
        ]
    parsed_reply = DefenseReply.model_validate(reply)
    return {
        "host_id": "synthetic-a",
        "request_id": rid,
        "kind": kind,
        "phase": state,
        "mode": mode,
        "mode_revision": 3,
        "manifest": None
        if kind == "cursor"
        else {
            "sha256": "d" * 64,
            "ttl_ms": 60000,
            "source_ref": SOURCE,
            "source_alias": "fixture-a",
            "deadline_at": stamp(110),
        },
        "current_result": parsed_reply.model_dump(mode="json"),
        "last_confirmed": None
        if kind == "cursor"
        else ConfirmedMetadata(
            rid=rid,
            state=state,
            observed_at=stamp(-1),
            remaining_ms=parsed_reply.remaining_ms,
            receipt_sha256="8" * 64,
        ).model_dump(mode="json"),
        "query_required": False,
        "reason_code": "ok",
        "history": [
            ObservationMetadata(
                observation_id="9" * 32,
                rid=rid,
                op=parsed_reply.op,
                state=state,
                observed_at=stamp(-2),
                receipt_sha256="8" * 64,
                accepted=True,
                reason="ok",
            ).model_dump(mode="json")
        ],
    }


class Contract:
    def __init__(
        self,
        *,
        enabled=True,
        mode="assisted",
        lose_apply=False,
        ai_required=True,
        synchronized=True,
    ):
        self.enabled, self.mode, self.lose_apply = enabled, mode, lose_apply
        self.ai_required = ai_required
        self.synchronized = synchronized
        self.calls = []
        self.rows = {}
        self.errors = []
        self.hold_mode_save = False
        self.pending_mode_route = None

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not path.startswith("/api/"):
            filename = "index.html" if path == "/" else path.lstrip("/")
            if filename not in {"index.html", "app.js", "defense.js", "styles.css"}:
                route.abort()
                return
            content_type = (
                "text/javascript"
                if filename.endswith(".js")
                else "text/css"
                if filename.endswith(".css")
                else "text/html"
            )
            route.fulfill(body=(ROOT / "web" / filename).read_bytes(), content_type=content_type)
            return
        body = request.post_data_json if request.post_data else None
        self.calls.append((request.method, path, body))
        if path != "/api/status":
            assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == "/api/automation" and request.method == "PUT" and self.hold_mode_save:
            assert body == {"mode": "manual", "expected_revision": 3}
            assert self.pending_mode_route is None
            self.pending_mode_route = route
            return
        base = "/api/hosts/synthetic-a/ssh-defense/"
        if path == "/api/ssh-defense/status":
            wire_mode = "manual" if self.mode == "manual" else "semi"
            value = {
                "configured": self.enabled,
                "enabled": self.enabled,
                "disabled": not self.enabled,
                "limited_profile": "private-198.18.241.0/28",
                "ttl_ms": 60000,
                "mode": self.mode,
                "revision": 3,
                "sync_generation": 1,
                "mode_sync_complete": self.synchronized,
                "ai_required": self.ai_required,
                "reason_code": "ok" if self.enabled else "disabled",
                "targets": [
                    {
                        "host_id": "synthetic-a",
                        "mode_ack": ModeAckMetadata(
                            context=DefenseContext(
                                host_id="synthetic-a",
                                defense_scope="4" * 64,
                                registry_scope="5" * 64,
                                root_scope="1" * 64,
                                policy_sha256=POLICY_SHA256,
                                boot_ref="2" * 64,
                                binding_ref="3" * 64,
                                mode=wire_mode,
                                global_revision=3,
                                wire_revision=4,
                                epoch=1,
                            ),
                            mode_rid="b" * 32,
                            status="confirmed" if self.synchronized else "pending",
                            checked_at=stamp(),
                            receipt_sha256="c" * 64 if self.synchronized else None,
                        ).model_dump(mode="json"),
                        "observation_available": self.enabled,
                        "execution_available": (
                            self.enabled and self.mode != "manual" and self.synchronized
                        ),
                        "reconciliation_required": False,
                    }
                ],
            }
        elif path == base + "transactions":
            value = {"transactions": list(self.rows.values())}
        elif path == base + "arm":
            assert body == {"expected_mode_revision": 3, "confirm_arm": True}
            value = transaction(
                "cursor", "armed", mode="manual" if self.mode == "manual" else "semi"
            )
            self.rows[CURSOR] = value
        elif path == base + "transactions/" + CURSOR + "/query":
            assert body == {}
            value = transaction(
                "cursor", "attached", mode="manual" if self.mode == "manual" else "semi"
            )
            self.rows[CURSOR] = value
        elif path == base + "ai/preview":
            value = {
                "v": 1,
                "input_digest": "c" * 64,
                "input": ModelInput(
                    v=1,
                    candidates=(
                        ModelCandidate(
                            candidate_alias="candidate-1",
                            evidence_alias="evidence-1",
                            classification="eligible",
                            distinct_failure_ports=5,
                            ttl_seconds=60,
                        ),
                    ),
                    omitted_candidate_count=0,
                ).model_dump(mode="json"),
                "provider_fingerprint": "f" * 64,
                "mode_revision": 3,
                "actions_executable": False,
            }
        elif path == base + "ai/analyses":
            assert body == {
                "cursor_request_id": CURSOR,
                "source_ref": SOURCE,
                "expected_input_digest": "c" * 64,
                "expected_mode_revision": 3,
                "confirm_send": True,
            }
            value = {
                "v": 1,
                "analysis_id": ANALYSIS,
                "input_digest": "c" * 64,
                "status": "unknown",
                "decision": None,
                "reason_code": None,
                "proof_sha256": None,
                "actions_executable": False,
            }
        elif path == base + "ai/analyses/" + ANALYSIS:
            value = {
                "v": 1,
                "analysis_id": ANALYSIS,
                "input_digest": "c" * 64,
                "status": "completed",
                "decision": "propose_defense",
                "reason_code": "evidence_sufficient",
                "proof_sha256": "a" * 64,
                "actions_executable": False,
            }
        elif path == base + "prepare":
            assert body == {
                "cursor_request_id": CURSOR,
                "source_ref": SOURCE,
                "expected_evidence_sha256": "e" * 64,
                "expected_mode_revision": 3,
            }
            value = transaction("action", "ready")
            self.rows[ACTION] = value
        elif path == base + "transactions/" + ACTION + "/apply":
            assert body == {
                "expected_manifest_sha256": "d" * 64,
                "expected_mode_revision": 3,
                "confirm_execute": True,
            }
            value = transaction("action", "active")
            self.rows[ACTION] = value
            if self.lose_apply:
                route.abort("connectionreset")
                return
        elif path == base + "transactions/" + ACTION + "/query":
            assert body == {}
            value = copy.deepcopy(self.rows[ACTION])
            value["current_result"]["op"] = "query"
            value["current_result"] = DefenseReply.model_validate(
                value["current_result"]
            ).model_dump(mode="json")
            value["history"].append(
                ObservationMetadata(
                    observation_id="a" * 32,
                    rid=ACTION,
                    observed_at=stamp(),
                    op="query",
                    state=value["phase"],
                    receipt_sha256="b" * 64,
                    accepted=True,
                    reason="ok",
                ).model_dump(mode="json")
            )
            self.rows[ACTION] = value
        elif path == base + "transactions/" + ACTION + "/revoke":
            assert body == {
                "expected_manifest_sha256": "d" * 64,
                "expected_mode_revision": 3,
                "confirm_revoke": True,
            }
            value = transaction("action", "revoked")
            self.rows[ACTION] = value
        elif path.startswith(base + "transactions/"):
            value = self.rows[path.rsplit("/", 1)[-1]]
        else:
            payloads = {
                "/api/status": {"version": "synthetic-defense-contract"},
                "/api/capabilities": {
                    "mode": "read_only",
                    "automation_modes": True,
                    "ssh_defense_transactions": self.enabled,
                    "security_observation": False,
                },
                "/api/samples": [],
                "/api/reports": [],
                "/api/hosts": [
                    {
                        "id": "synthetic-a",
                        "name": "合成隔离目标 " + UNTRUSTED,
                        "source": "ssh",
                        "address": "192.0.2.1",
                    },
                    {
                        "id": "synthetic-b",
                        "name": "只读登记，无防护凭据",
                        "source": "ssh",
                        "address": "192.0.2.2",
                    },
                ],
                "/api/automation": {
                    "mode": self.mode,
                    "revision": 3,
                    "sync_generation": 1,
                    "mode_sync_complete": self.synchronized,
                    "execution_available": False,
                },
            }
            assert path in payloads, path
            value = payloads[path]
        route.fulfill(content_type="application/json", body=json.dumps(value))

    def count(self, suffix):
        return sum(path.endswith(suffix) and method == "POST" for method, path, _ in self.calls)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Error as error:
            pytest.skip("Playwright Chromium unavailable: " + type(error).__name__)
        yield instance
        instance.close()


@pytest.fixture
def console(browser):
    # This server is a loopback anchor only; every resource/API request is intercepted.
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_error(404)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    contexts = []

    def open_console(**options):
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        contexts.append(context)
        page = context.new_page()
        factory = options.pop("_contract", Contract)
        contract = factory(**options)
        page.on("pageerror", lambda error: contract.errors.append(str(error)))
        page.route("**/*", contract.route)
        page.goto(f"http://127.0.0.1:{server.server_port}")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        page.locator('button[data-view="security"]').click()
        expect(page.locator("#ssh-defense-workspace")).to_be_visible()
        return page, contract

    yield open_console
    for context in contexts:
        context.close()
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def confirm(page):
    expect(page.locator('[data-defense="dialog"]')).to_be_visible()
    expect(page.locator('[data-defense="send"]')).to_be_disabled()
    page.locator('[data-defense="confirm"]').check()
    page.locator('[data-defense="send"]').click()


def armed_source(page):
    arm = page.locator('[data-defense="arm"]')
    expect(arm).to_be_enabled()
    arm.click()
    confirm(page)
    page.get_by_role("button", name="查询同一个原任务", exact=True).click()
    page.locator('[name="ssh-defense-source"]').check()
    expect(page.locator('[data-defense="sources"]')).to_contain_text("fixture-a")
    expect(page.locator('[data-defense="host"]')).to_contain_text(UNTRUSTED)


def test_exact_confirmation_unknown_receipt_query_and_revoke(console):
    page, contract = console(lose_apply=True)
    armed_source(page)
    page.get_by_role("button", name="预览 AI 白名单摘要", exact=True).click()
    page.get_by_role("button", name="核对白名单并批准这次发送", exact=True).click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(
        '"candidate_alias": "candidate-1"'
    )
    expect(page.locator('[data-defense="dialog-summary"]')).not_to_contain_text("192.0.2.1")
    confirm(page)
    expect(page.locator('[data-defense="ai"]')).to_contain_text("unknown")
    expect(page.get_by_role("button", name="准备处置清单（不执行）", exact=True)).to_be_disabled()
    page.get_by_role("button", name="查询原分析，不重新发送", exact=True).click()
    expect(page.locator('[data-defense="ai"]')).to_contain_text("建议固定处置")
    page.get_by_role("button", name="准备处置清单（不执行）", exact=True).click()
    apply = page.get_by_role("button", name="核对并执行这份清单", exact=True)
    apply.click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text("d" * 64)
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(ACTION)
    confirm(page)
    expect(page.locator('[data-defense="detail"]')).to_contain_text("结果未确认，只查询原任务")
    expect(apply).to_be_disabled()
    expect(page.get_by_role("button", name="核对并撤销原动作", exact=True)).to_be_disabled()
    assert contract.count("/apply") == 1
    page.get_by_role("button", name="查询同一个原任务", exact=True).click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text("最近确认生效")
    expect(page.locator('[data-defense="detail"]')).to_contain_text("历史回执 · 2 条")
    expect(apply).to_be_disabled()
    page.get_by_role("button", name="核对并撤销原动作", exact=True).click()
    confirm(page)
    expect(page.locator('[data-defense="detail"]')).to_contain_text("最近确认已撤销")
    assert contract.count("/arm") == contract.count("/prepare") == contract.count("/apply") == 1
    assert contract.count("/ai/analyses") == contract.count("/revoke") == 1
    assert page.locator("#ssh-defense-workspace img").count() == 0
    assert page.evaluate("window.defenseInjected === undefined")
    assert not contract.errors


def test_manual_mode_advice_has_no_execution_and_logout_clears(console):
    page, contract = console(mode="manual")
    armed_source(page)
    expect(page.get_by_role("button", name="准备处置清单（不执行）", exact=True)).to_be_disabled()
    page.get_by_role("button", name="预览 AI 白名单摘要", exact=True).click()
    page.get_by_role("button", name="核对白名单并批准这次发送", exact=True).click()
    page.locator('[data-defense="confirm"]').check()
    page.locator("[data-defense=cancel]").click()
    assert contract.count("/ai/analyses") == 0
    page.get_by_role("button", name="核对白名单并批准这次发送", exact=True).click()
    expect(page.locator('[data-defense="confirm"]')).not_to_be_checked()
    expect(page.locator('[data-defense="send"]')).to_be_disabled()
    confirm(page)
    expect(page.locator('[data-defense="ai"]')).to_contain_text(ANALYSIS)
    page.locator("#logout-button").click()
    expect(page.locator("#login-screen")).to_be_visible()
    expect(page.locator("#ssh-defense-workspace")).to_be_hidden()
    expect(page.locator('[data-defense="dialog-summary"]')).to_be_empty()
    assert contract.count("/prepare") == contract.count("/apply") == 0
    assert not contract.errors


def test_disabled_default_opens_no_authority_and_mobile_fits(console):
    page, contract = console(enabled=False)
    page.set_viewport_size({"width": 390, "height": 844})
    expect(page.locator('[data-defense="status"]')).to_contain_text("防护执行默认关闭")
    expect(page.locator('[data-defense="arm"]')).to_be_disabled()
    assert not any(method == "POST" for method, _, _ in contract.calls)
    assert not any("/ssh-defense/" in path for _, path, _ in contract.calls)
    assert page.locator("#ssh-defense-workspace").evaluate("el=>el.scrollWidth<=el.clientWidth")
    assert not contract.errors


def test_global_mode_refresh_invalidates_open_exact_confirmation(console):
    page, contract = console(ai_required=False)
    armed_source(page)
    page.get_by_role("button", name="准备处置清单（不执行）", exact=True).click()
    page.get_by_role("button", name="核对并执行这份清单", exact=True).click()
    page.locator('[data-defense="confirm"]').check()
    # A mode refresh arriving from another surface invalidates the open approval.
    page.evaluate("document.querySelector('#refresh-automation').click()")
    expect(page.locator('[data-defense="dialog"]')).to_be_hidden()
    expect(page.get_by_role("button", name="核对并执行这份清单", exact=True)).to_be_disabled()
    assert contract.count("/apply") == 0
    assert not contract.errors


def test_unsynchronized_global_mode_does_not_arm(console):
    page, contract = console(synchronized=False)
    expect(page.locator('[data-defense="status"]')).to_contain_text("禁止新动作")
    expect(page.locator('[data-defense="arm"]')).to_be_disabled()
    assert not any(method == "POST" for method, _, _ in contract.calls)
    assert not contract.errors


def test_changing_to_unregistered_defense_target_clears_old_source(console):
    page, contract = console()
    armed_source(page)
    page.locator('[data-defense="host"]').select_option("synthetic-b")
    expect(page.locator('[data-defense="progress"]')).to_contain_text("所选目标未登记事务专用凭据")
    expect(page.locator('[data-defense="sources"]')).to_be_empty()
    expect(page.locator('[data-defense="history"]')).not_to_contain_text(CURSOR)
    expect(page.locator('[data-defense="arm"]')).to_be_disabled()
    page.locator('[data-defense="host"]').select_option("synthetic-a")
    expect(page.locator('[data-defense="history"]')).to_contain_text(CURSOR)
    page.locator(".ssh-defense-row").click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text(CURSOR)
    expect(page.locator('[data-defense="sources"]')).to_contain_text("fixture-a")
    assert contract.count("/arm") == 1
    assert not contract.errors


def test_pending_real_mode_save_closes_confirmation_and_never_dispatches(console):
    page, contract = console(ai_required=False)
    armed_source(page)
    page.get_by_role("button", name="准备处置清单（不执行）", exact=True).click()
    apply = page.get_by_role("button", name="核对并执行这份清单", exact=True)
    apply.click()
    page.locator('[data-defense="confirm"]').check()
    contract.hold_mode_save = True
    with page.expect_request(
        lambda request: urlsplit(request.url).path == "/api/automation" and request.method == "PUT"
    ):
        # Use the real saveAutomation handler; do not manufacture a getContext value.
        page.evaluate(
            """() => {
                const select = document.querySelector('#automation-mode-select');
                select.value = 'manual';
                select.dispatchEvent(new Event('change', {bubbles:true}));
                document.querySelector('#automation-mode-form').requestSubmit();
            }"""
        )
    expect(page.locator('[data-defense="dialog"]')).to_be_hidden()
    expect(page.locator("#save-automation-mode")).to_have_text("正在读取或保存…")
    expect(apply).to_be_disabled()
    assert contract.pending_mode_route is not None
    assert contract.count("/apply") == 0
    # Even a fresh defense read cannot clear the independent pending global save.
    page.locator('[data-defense="refresh"]').click()
    expect(page.locator('[data-defense="progress"]')).to_contain_text("已读取本地记录")
    expect(apply).to_be_disabled()
    expect(page.locator('[data-defense="arm"]')).to_be_disabled()
    assert contract.count("/apply") == 0
    contract.pending_mode_route.fulfill(
        status=409,
        content_type="application/json",
        body=json.dumps({"detail": "Synthetic mode save not confirmed"}),
    )
    expect(page.locator("#automation-error")).to_be_visible()
    expect(apply).to_be_disabled()
    assert sum(method == "PUT" for method, _, _ in contract.calls) == 1
    assert contract.count("/apply") == 0
    assert not contract.errors
