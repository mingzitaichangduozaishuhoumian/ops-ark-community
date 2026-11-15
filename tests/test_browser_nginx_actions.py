"""Chromium contracts for the Nginx panel with all requests fulfilled locally."""

import copy
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import (
    PRIVATE,
    ROOT,
    TOKEN,
    ComposeContract,
    launch_fixture_browser,
)
from playwright.sync_api import expect, sync_playwright

BASE = "/api/nginx-actions"
FIRST, SECOND = "a" * 32, "b" * 32


class Contract(ComposeContract):
    def __init__(
        self,
        *,
        enabled=True,
        hold=False,
        mode="assisted",
        invalid=False,
        observation="verified",
        expired=False,
        approval_http=None,
    ):
        super().__init__()
        self.base = "http://127.0.0.1:18496"
        self.enabled, self.hold, self.invalid = enabled, hold, invalid
        self.mode, self.revision = mode, 17
        self.observation, self.expired = observation, expired
        self.approval_http = approval_http
        self.hosts = {"site-a": "1" * 64, "site-b": "2" * 64}
        self.records, self.held, self.operations = {}, None, []
        self.asset_requests = 0

    @staticmethod
    def reply(route, value):
        route.fulfill(content_type="application/json", body=json.dumps(value))

    def plan(self, host, original=None):
        plan_id = SECOND if original else FIRST
        now = datetime.now(UTC)
        before, after = (18082, 18081) if original else (18081, 18082)
        source, candidate = ("c", "d") if original else ("d", "c")
        value = {
            "plan_id": plan_id,
            "host_id": host,
            "status": "ready",
            "created_at": now.isoformat(),
            "approved": False,
            "blocking": False,
            "plan": {
                "schema_version": 1,
                "status": "ready",
                "plan_id": plan_id,
                "action": "restore" if original else "apply",
                "action_id": plan_id[0] * 64,
                "policy_digest": "e" * 64,
                "plan_digest": ("9" if original else "8") * 64,
                "mode_revision": self.revision,
                "source_sha256": source * 64,
                "candidate_sha256": candidate * 64,
                "backup_sha256": "d" * 64,
                "context_sha256": "f" * 64,
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "upstream_before": f"127.0.0.1:{before}",
                "upstream_after": f"127.0.0.1:{after}",
                "affected_site_ids": ["shop", "shared"],
                "syntax": "passed",
                "original_action_id": original["plan"]["action_id"] if original else None,
            },
            "receipt": None,
            "prepare_reason": None,
        }
        self.records[plan_id] = value
        return value

    @staticmethod
    def record_result(record, status, *, reconciliation=None):
        plan = record["plan"]
        receipt = {
            "schema_version": 1,
            "status": status,
            **{
                key: plan[key]
                for key in (
                    "action_id",
                    "action",
                    "policy_digest",
                    "plan_id",
                    "plan_digest",
                    "mode_revision",
                )
            },
            "reason": {
                "verified": None,
                "unknown": "business_unconfirmed",
                "not_started": "expired",
            }[status],
            "reconciliation_status": reconciliation,
        }
        record.update(
            status=status,
            approved=True,
            receipt=receipt,
            blocking=status == "unknown"
            and reconciliation not in {"verified", "unchanged_from_preview"},
        )

    def route(self, route):
        request = route.request
        if not request.url.startswith(self.base + "/"):
            return super().route(route)
        path = urlsplit(request.url).path
        if path in {"/nginx-dependencies.js", "/nginx-actions.js"}:
            self.asset_requests += int(path == "/nginx-actions.js")
            return route.fulfill(
                content_type="text/javascript", body=(ROOT / "web" / path.lstrip("/")).read_bytes()
            )
        if path == "/api/capabilities":
            return self.reply(
                route,
                {
                    "mode": "read_only",
                    "nginx_managed_actions": self.enabled,
                    "automation_modes": True,
                },
            )
        if path == "/api/automation":
            assert request.method == "GET"
            return self.reply(
                route,
                {
                    "mode": self.mode,
                    "revision": self.revision,
                    "mode_sync_complete": True,
                    "execution_available": False,
                },
            )
        if path == "/api/hosts":
            return self.reply(
                route,
                [
                    {
                        "id": host,
                        "name": host,
                        "source": "ssh",
                        "address": "192.0.2.2",
                        "port": 22,
                        "username": "opsark-readonly",
                        "trusted_hosts_digest": "a" * 64,
                        "nginx_action_configured": digest is not None,
                        "nginx_action_binding_digest": digest,
                    }
                    for host, digest in [*self.hosts.items(), ("readonly-host", None)]
                ],
            )
        if not path.startswith(BASE):
            return super().route(route)

        method = request.method
        body = request.post_data_json if request.post_data else None
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        self.operations.append((method, path, body))
        if path == BASE:
            assert method == "GET"
            return self.reply(route, list(self.records.values()))
        if path == f"{BASE}/prepare":
            assert method == "POST"
            host = body["host_id"]
            assert host in self.hosts and body == {
                "host_id": host,
                "expected_mode_revision": self.revision,
            }
            row = self.plan(host)
            response = copy.deepcopy(row)
            if self.invalid:
                response["plan"]["raw_config"] = PRIVATE
            if self.hold:
                self.held = (route, response)
                return
            return self.reply(route, response)
        path_parts = path.removeprefix(BASE + "/").split("/")
        record = self.records[path_parts[0]]
        if len(path_parts) == 1:
            assert method == "GET" and body is None
            if self.expired and record["status"] == "unknown":
                self.record_result(record, "not_started")
            return self.reply(route, record)
        if path_parts[1:] == ["rollback", "prepare"]:
            assert method == "POST" and body == {"expected_mode_revision": self.revision}
            return self.reply(route, self.plan(record["host_id"], original=record))
        if path_parts[1:] == ["observe"]:
            assert method == "POST" and body is None and record["approved"]
            self.record_result(record, "unknown", reconciliation=self.observation)
            return self.reply(route, record)
        if path_parts[1:] == ["approve"]:
            assert method == "POST" and body == {
                "expected_plan_digest": record["plan"]["plan_digest"],
                "expected_mode_revision": self.revision,
                "confirm": True,
            }
            if self.approval_http:
                return route.fulfill(
                    status=self.approval_http,
                    content_type="application/json",
                    body=json.dumps({"detail": PRIVATE}),
                )
            if record["plan"]["action"] == "apply":
                self.record_result(record, "unknown")
                route.abort()
            else:
                self.record_result(record, "verified")
                original = self.records[FIRST]
                if original["receipt"]["reconciliation_status"] == "disk_published_live_previous":
                    assert record["plan"]["original_action_id"] == original["plan"]["action_id"]
                    original["blocking"] = False
                self.reply(route, record)
            return
        raise AssertionError("Unexpected Nginx action route")

    def release(self):
        route, value = self.held
        self.held = None
        self.reply(route, value)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_fixture_browser(playwright)
        yield instance
        instance.close()


@pytest.fixture
def console(browser):
    contexts, contracts = [], []

    def open_console(width=1440, **options):
        contract = Contract(**options)
        contracts.append(contract)
        context = browser.new_context(
            viewport={"width": width, "height": 930}, service_workers="block"
        )
        contexts.append(context)
        page = context.new_page()
        page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
        page.route("**/*", contract.route)
        page.goto(contract.base)
        page.wait_for_load_state("networkidle")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        if contract.enabled:
            page.locator("#remediation-nav").click()
            expect(page.locator("#nginx-actions-section")).to_be_visible()
        return page, contract

    yield open_console
    for context in contexts:
        context.close()
    assert all(not c.errors and not any(c.counts.values()) for c in contracts)


def preview(page):
    panel = page.locator("#nginx-actions-section")
    panel.get_by_role("button", name="生成变更预览").click()
    expect(panel.get_by_role("article", name="原计划与回执")).to_contain_text(FIRST)
    return panel


@pytest.mark.parametrize("width", [320, 1440])
def test_exact_preview_lost_approval_query_observe_and_separately_approve_rollback(console, width):
    page, contract = console(width=width)
    panel = preview(page)
    assert panel.locator("#nginx-action-host option").count() == 2
    expect(page.locator("#remediation-patch-workspace")).to_be_hidden()
    expect(panel).to_contain_text("shop、shared")
    expect(panel).to_contain_text("127.0.0.1:18081")
    expect(panel).to_contain_text("127.0.0.1:18082")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    panel.get_by_role("button", name="核对批准").click()
    dialog = panel.get_by_role("dialog")
    expect(dialog).to_contain_text("8" * 64)
    expect(dialog).to_contain_text("17")
    expect(dialog.get_by_role("button", name="批准变更")).to_be_disabled()
    dialog.get_by_role("checkbox").check()
    dialog.get_by_role("button", name="批准变更").click()
    expect(panel.get_by_role("alert")).to_contain_text("请查询原计划")
    assert [row[1] for row in contract.operations] == [f"{BASE}/prepare", f"{BASE}/{FIRST}/approve"]
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.locator("#nginx-action-host").select_option("site-b")
    expect(panel).not_to_contain_text(FIRST)
    panel.locator("#nginx-action-host").select_option("site-a")
    panel.get_by_role("button", name="查询原计划").click()
    expect(panel.get_by_role("button", name="独立复验原动作")).to_be_enabled()
    panel.get_by_role("button", name="独立复验原动作").click()
    expect(panel).to_contain_text("独立复验通过 · 原结果未知")
    panel.get_by_role("button", name="生成回退预览").click()
    expect(panel.get_by_role("article")).to_contain_text(SECOND)
    panel.get_by_role("button", name="核对批准").click()
    expect(dialog).to_contain_text("9" * 64)
    expect(dialog.get_by_role("button", name="批准回退")).to_be_disabled()
    dialog.get_by_role("checkbox").check()
    dialog.get_by_role("button", name="批准回退").click()
    expect(panel.get_by_role("article").get_by_role("heading")).to_have_text("已验证")
    assert [(row[0], row[1]) for row in contract.operations] == [
        ("POST", f"{BASE}/prepare"),
        ("POST", f"{BASE}/{FIRST}/approve"),
        ("GET", f"{BASE}/{FIRST}"),
        ("POST", f"{BASE}/{FIRST}/observe"),
        ("POST", f"{BASE}/{FIRST}/rollback/prepare"),
        ("POST", f"{BASE}/{SECOND}/approve"),
    ]


@pytest.mark.parametrize("change", ["mode", "host"])
def test_changed_mode_or_host_binding_refuses_before_approval(console, change):
    page, contract = console()
    panel = preview(page)
    panel.get_by_role("button", name="核对批准").click()
    dialog = panel.get_by_role("dialog")
    dialog.get_by_role("checkbox").check()
    if change == "host":
        contract.hosts["site-a"] = "3" * 64
    else:
        contract.revision += 1
    dialog.get_by_role("button", name="批准变更").click()
    expect(panel.get_by_role("alert")).to_be_visible()
    assert [op[1] for op in contract.operations] == [f"{BASE}/prepare"]


@pytest.mark.parametrize("change", ["host", "logout"])
def test_late_preview_cannot_cross_host_selection_or_logout(console, change):
    page, contract = console(hold=True)
    panel = page.locator("#nginx-actions-section")
    with page.expect_request(lambda req: req.url.endswith(f"{BASE}/prepare")):
        panel.get_by_role("button", name="生成变更预览").click()
    expect(panel.get_by_role("status")).to_have_text("正在核对预览…")
    if change == "host":
        panel.locator("#nginx-action-host").select_option("site-b")
        panel.locator("#nginx-action-host").select_option("site-a")
    else:
        page.locator("#logout-button").click()
        expect(page.locator("#login-screen")).to_be_visible()
    contract.release()
    page.wait_for_load_state("networkidle")
    assert panel.get_by_role("article").count() == 0
    assert panel.get_by_role("dialog").count() == 0
    assert len(contract.operations) == 1


def test_malformed_preview_is_wholly_rejected(console):
    page, contract = console(invalid=True)
    panel = page.locator("#nginx-actions-section")
    panel.get_by_role("button", name="生成变更预览").click()
    expect(panel.get_by_role("alert")).to_be_visible()
    assert PRIVATE not in page.locator("body").inner_text()
    assert panel.get_by_role("article").count() == 0
    assert len(contract.operations) == 1


def test_manual_mode_previews_but_cannot_approve(console):
    page, contract = console(mode="manual")
    panel = preview(page)
    expect(panel.get_by_role("button", name="核对批准")).to_be_disabled()
    assert len(contract.operations) == 1


def test_historical_ready_preview_can_be_read_but_not_approved(console):
    page, contract = console()
    contract.plan("site-a")
    panel = page.locator("#nginx-actions-section")
    panel.get_by_role("button", name="读取处置记录").click()
    expect(panel.get_by_role("article")).to_contain_text(FIRST)
    expect(panel.get_by_role("button", name="核对批准")).to_be_disabled()
    with page.expect_request(
        lambda req: req.method == "GET" and req.url.endswith(f"{BASE}/{FIRST}")
    ):
        panel.get_by_role("button", name="查询原计划").click()
    expect(panel.get_by_role("article")).to_contain_text("历史预览可查询")
    expect(panel.get_by_role("button", name="核对批准")).to_be_disabled()
    assert contract.operations == [("GET", BASE, None), ("GET", f"{BASE}/{FIRST}", None)]


def apply_with_lost_ack(panel):
    panel.get_by_role("button", name="核对批准").click()
    dialog = panel.get_by_role("dialog")
    dialog.get_by_role("checkbox").check()
    dialog.get_by_role("button", name="批准变更").click()
    expect(panel.get_by_role("alert")).to_contain_text("请查询原计划")


@pytest.mark.parametrize("http_status", [403, 409, 503])
def test_rejected_approval_needs_original_get_before_any_new_preview(console, http_status):
    page, contract = console(approval_http=http_status)
    panel = preview(page)
    apply_with_lost_ack(panel)
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.get_by_role("button", name="查询原计划").click()
    expect(panel.get_by_role("button", name="查询原计划")).to_be_enabled()
    if http_status == 503:
        expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    else:
        expect(panel.get_by_role("button", name="生成变更预览")).to_be_enabled()
        expect(panel.get_by_role("button", name="核对批准")).to_be_disabled()
    assert PRIVATE not in page.locator("body").inner_text()
    assert [row[1] for row in contract.operations] == [
        f"{BASE}/prepare",
        f"{BASE}/{FIRST}/approve",
        f"{BASE}/{FIRST}",
    ]


def test_expired_original_approval_is_not_started_and_allows_new_preview(console):
    page, contract = console(expired=True)
    panel = preview(page)
    apply_with_lost_ack(panel)
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.get_by_role("button", name="查询原计划").click()
    expect(panel.get_by_role("article")).to_contain_text("未开始 · 已核实")
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_enabled()
    expect(panel.get_by_role("button", name="核对批准")).to_have_count(0)
    assert [row[1] for row in contract.operations] == [
        f"{BASE}/prepare",
        f"{BASE}/{FIRST}/approve",
        f"{BASE}/{FIRST}",
    ]


def test_original_receipt_remains_unknown_after_proving_no_change(console):
    page, contract = console(observation="unchanged_from_preview")
    panel = preview(page)
    apply_with_lost_ack(panel)
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.get_by_role("button", name="查询原计划").click()
    panel.get_by_role("button", name="独立复验原动作").click()
    expect(panel.get_by_role("article").get_by_role("heading")).to_have_text(
        "配置和服务已核实未变 · 原结果未知"
    )
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_enabled()
    expect(panel.get_by_role("button", name="核对批准")).to_have_count(0)
    expect(panel.get_by_role("button", name="生成回退预览")).to_have_count(0)
    assert [row[1] for row in contract.operations] == [
        f"{BASE}/prepare",
        f"{BASE}/{FIRST}/approve",
        f"{BASE}/{FIRST}",
        f"{BASE}/{FIRST}/observe",
    ]


def test_published_disk_live_previous_allows_only_original_rollback_until_verified(console):
    page, contract = console(observation="disk_published_live_previous")
    panel = preview(page)
    apply_with_lost_ack(panel)
    panel.get_by_role("button", name="查询原计划").click()
    panel.get_by_role("button", name="独立复验原动作").click()
    expect(panel.get_by_role("article")).to_contain_text("磁盘已变更 · 原服务已复验")
    expect(panel.get_by_role("article")).to_contain_text("原变更结果未知")
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.get_by_role("button", name="生成回退预览").click()
    expect(panel.get_by_role("article")).to_contain_text(SECOND)
    panel.get_by_role("button", name="核对批准").click()
    dialog = panel.get_by_role("dialog")
    expect(dialog.get_by_role("button", name="批准回退")).to_be_disabled()
    dialog.get_by_role("checkbox").check()
    dialog.get_by_role("button", name="批准回退").click()
    expect(panel.get_by_role("article").get_by_role("heading")).to_have_text("已验证")
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_disabled()
    panel.locator(f'[data-nginx-plan-id="{FIRST}"]').click()
    panel.get_by_role("button", name="查询原计划").click()
    expect(panel.get_by_role("article").get_by_role("heading")).to_have_text(
        "回退已核实 · 原结果未知"
    )
    expect(panel.get_by_role("button", name="生成变更预览")).to_be_enabled()
    assert [row[1] for row in contract.operations] == [
        f"{BASE}/prepare",
        f"{BASE}/{FIRST}/approve",
        f"{BASE}/{FIRST}",
        f"{BASE}/{FIRST}/observe",
        f"{BASE}/{FIRST}/rollback/prepare",
        f"{BASE}/{SECOND}/approve",
        f"{BASE}/{FIRST}",
    ]


def test_disabled_capability_does_not_load_panel_script(console):
    page, contract = console(enabled=False)
    expect(page.locator("#remediation-nav")).to_be_hidden()
    assert not contract.asset_requests and not contract.operations
