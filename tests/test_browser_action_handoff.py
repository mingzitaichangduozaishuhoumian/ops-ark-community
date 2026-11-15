"""Browser contract for saved-report action linking and handoff using local fakes."""

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from browser_compose_discovery_smoke import (
    PRIVATE,
    ROOT,
    TOKEN,
    ComposeContract,
    launch_fixture_browser,
)
from playwright.sync_api import expect, sync_playwright
from test_browser_nginx_actions import Contract as NginxContract

REPORT = "saved-ssh-report"
OTHER = "another-saved-report"
PLAN = "a" * 32
RESTORE = "b" * 32
ACTION_URL = f"/api/reports/{REPORT}/handoff-actions"
AT = datetime(2026, 11, 13, 4, tzinfo=UTC).isoformat()


class Contract(ComposeContract):
    def __init__(self, *, enabled=True, mismatch=False):
        super().__init__()
        self.base = "http://127.0.0.1:18556"
        self.enabled = enabled
        self.mismatch = mismatch
        self.operations = []
        self.rechecks = []
        self.next_verdict = "failed"
        self.drop = False
        self.hold_history = False
        self.nginx = NginxContract()
        self.host = {
            "id": "site-a",
            "name": "Same registered host",
            "source": "ssh",
            "address": "192.0.2.2",
            "port": 22,
            "username": "opsark-readonly",
            "site_domain": "private-site.invalid",
            "container_name": "synthetic-container",
            "expected_upstream_port": 8081,
            "trusted_hosts_digest": "a" * 64,
            "nginx_config_path": None,
            "health_checks": [],
        }

    @staticmethod
    def reply(route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def report(self, report_id):
        target = self.host | ({"username": "other-role"} if self.mismatch else {})
        return {
            "id": report_id,
            "host_id": self.host["id"],
            "host_name": self.host["name"],
            "scope_hash": "8" * 64,
            "scenario": "web_502",
            "status": "inconclusive",
            "source": "ssh",
            "created_at": AT,
            "title": "Report A" if report_id == REPORT else "Report B",
            "summary": "synthetic diagnostic summary",
            "duration_ms": 1,
            "target": target,
            "facts": [],
            "candidates": [],
            "missing": [],
            "evidence": [],
            "next_steps": [],
        }

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/") or not path.startswith("/api/"):
            if path in {"/nginx-actions.js", "/container-restarts.js", "/nginx-dependencies.js"}:
                return route.fulfill(
                    content_type="text/javascript", body=(ROOT / "web" / path[1:]).read_bytes()
                )
            return super().route(route)
        if path != "/api/status":
            assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == "/api/capabilities":
            return self.reply(
                route,
                {
                    "mode": "read_only",
                    "automation_modes": True,
                    "nginx_managed_actions": True,
                    "container_restart": True,
                    "handoff_timeline": True,
                    "action_handoff": self.enabled,
                },
            )
        if path == "/api/automation":
            return self.reply(
                route, {"mode": "assisted", "revision": 17, "mode_sync_complete": True}
            )
        if path == "/api/hosts":
            return self.reply(
                route,
                [
                    self.host
                    | {
                        "nginx_action_configured": True,
                        "nginx_action_binding_digest": "b" * 64,
                        "container_restart_configured": True,
                        "container_restart_binding_digest": "c" * 64,
                    }
                ],
            )
        if path == "/api/reports":
            return self.reply(route, [self.report(REPORT), self.report(OTHER)])
        if path in {f"/api/reports/{REPORT}", f"/api/reports/{OTHER}"}:
            return self.reply(route, self.report(path.rsplit("/", 1)[1]))
        if path.endswith("/handoff-options"):
            return self.reply(route, {"jobs": [], "rechecks": []})
        if path == f"/api/reports/{OTHER}/handoff-actions":
            return self.reply(route, {"actions": []})
        if path == "/api/container-restarts":
            return self.reply(route, [])
        if path in {"/api/nginx-actions/prepare", "/api/container-restarts/prepare"}:
            body = request.post_data_json
            self.operations.append((request.method, path, body))
            if path.startswith("/api/nginx-actions"):
                return self.reply(route, self.nginx.plan(self.host["id"]))
            return self.reply(route, {"detail": PRIVATE}, status=409)
        if path == ACTION_URL:
            assert request.method == "GET"
            return self.reply(
                route,
                {
                    "actions": [
                        {"kind": "nginx", "plan_id": PLAN, "action": "apply", "approved_at": AT},
                        {
                            "kind": "nginx",
                            "plan_id": RESTORE,
                            "action": "restore",
                            "approved_at": AT,
                        },
                        {
                            "kind": "container_restart",
                            "plan_id": PLAN,
                            "action": "restart",
                            "approved_at": AT,
                        },
                    ]
                },
            )
        if path.startswith(ACTION_URL + "/"):
            return self.action_route(route, path)
        return super().route(route)

    def action_route(self, route, path):
        request = route.request
        query = parse_qs(urlsplit(request.url).query)
        self.operations.append((request.method, path, query))
        if path.endswith("/rechecks"):
            assert not request.post_data and not query
            if request.method == "POST":
                self.rechecks = [item | {"selection": "historical"} for item in self.rechecks]
                row = {
                    "id": "ar-" + f"{len(self.rechecks) + 1:032x}",
                    "selection": "current",
                    "verdict": self.next_verdict,
                    "started_at": AT,
                    "finished_at": AT,
                }
                self.rechecks.insert(0, row)
                if self.drop:
                    return route.abort()
                return self.reply(route, row)
            assert request.method == "GET"
            value = (
                {"can_run": True, "rechecks": self.rechecks}
                if f"/{PLAN}/" in path
                else {"can_run": False, "rechecks": []}
            )
            if self.hold_history:
                self.hold_history = False
                self.pending = (route, value)
                return None
            return self.reply(route, value)
        assert request.method == "GET"
        selected = query.get("recheck_id", [self.rechecks[0]["id"] if self.rechecks else ""])[0]
        verdict = next(
            (item["verdict"] for item in self.rechecks if item["id"] == selected), "pending"
        )
        return route.fulfill(
            content_type="text/markdown; charset=utf-8",
            body="# OpsArk 客户交接摘要\n"
            + {"passed": "复验通过", "failed": "复验未通过", "pending": "待验收"}[verdict],
        )


@pytest.fixture
def browser():
    with sync_playwright() as playwright, launch_fixture_browser(playwright) as instance:
        yield instance


def open_report(browser, contract, width=1200):
    page = browser.new_page(viewport={"width": width, "height": 900}, service_workers="block")
    page.on("pageerror", lambda error: contract.errors.append(str(error)))
    page.route("**/*", contract.route)
    page.goto(contract.base)
    page.wait_for_load_state("networkidle")
    page.locator("#token-input").fill(TOKEN)
    page.locator("#login-button").click()
    expect(page.locator("#app-shell")).to_be_visible()
    page.locator(f'[data-report-id="{REPORT}"]').click()
    expect(page.locator("#report-title")).to_have_text("Report A")
    return page


def open_dialog(page):
    page.locator("#export-handoff").click()
    expect(page.locator("#handoff-dialog")).to_be_visible()


@pytest.mark.parametrize("kind", ["nginx", "container_restart"])
def test_explicit_same_saved_report_link_only(kind, browser):
    contract = Contract()
    page = open_report(browser, contract)
    page.locator("#remediation-nav").click()
    if kind == "nginx":
        panel, label, path = "#nginx-actions-section", "生成变更预览", "/api/nginx-actions/prepare"
    else:
        panel, label, path = (
            "#container-restarts-section",
            "生成重启预览",
            "/api/container-restarts/prepare",
        )
    section = page.locator(panel)
    checkbox = section.get_by_role("checkbox", name="关联当前 SSH 调查报告")
    expect(checkbox).not_to_be_checked()
    checkbox.check()
    with page.expect_response("**" + path):
        section.get_by_role("button", name=label).click()
    assert contract.operations == [
        (
            "POST",
            path,
            {
                "host_id": "site-a",
                "expected_mode_revision": 17,
                "report_id": REPORT,
            },
        )
    ]
    assert not contract.errors


@pytest.mark.parametrize(("enabled", "mismatch"), [(False, False), (True, True)])
def test_no_link_with_old_backend_or_mismatched_report(browser, enabled, mismatch):
    contract = Contract(enabled=enabled, mismatch=mismatch)
    page = open_report(browser, contract)
    page.locator("#remediation-nav").click()
    panel = page.locator("#nginx-actions-section")
    expect(panel).to_be_visible()
    expect(panel.get_by_role("checkbox", name="关联当前 SSH 调查报告")).to_have_count(0)
    panel.get_by_role("button", name="生成变更预览").click()
    expect(panel.locator("[data-nginx-plan-id]")).to_have_count(1)
    assert contract.operations == [
        (
            "POST",
            "/api/nginx-actions/prepare",
            {
                "host_id": "site-a",
                "expected_mode_revision": 17,
            },
        )
    ]
    assert not contract.errors


def test_failure_pending_recovery_and_historical_download(browser):
    contract = Contract()
    page = open_report(browser, contract, width=390)
    open_dialog(page)
    picker = page.locator("#handoff-action")
    expect(picker.locator("option")).to_have_count(4)
    picker.select_option("nginx/" + PLAN)
    run = page.locator("#handoff-action-run")
    for verdict, label in [("failed", "复验未通过"), ("pending", "待验收"), ("passed", "复验通过")]:
        contract.next_verdict = verdict
        expect(run).to_be_enabled()
        run.click()
        expect(page.locator("#handoff-action-status")).to_have_text("当前复验 · " + label)
    assert page.locator("#handoff-dialog").evaluate("node => node.scrollWidth <= node.clientWidth")
    selected = contract.rechecks[-1]["id"]
    page.locator("#handoff-action-recheck").select_option(selected)
    expect(page.locator("#handoff-action-status")).to_have_text("历史复验 · 复验未通过")
    with page.expect_download() as downloaded:
        page.locator("#handoff-download").click()
    path = downloaded.value.path()
    text = path.read_text(encoding="utf-8")
    assert downloaded.value.suggested_filename == "opsark-handoff.md"
    assert "复验未通过" in text
    assert all(value not in text for value in (PRIVATE, REPORT, PLAN, selected, "192.0.2.2"))
    assert contract.operations[-1] == (
        "GET",
        f"{ACTION_URL}/nginx/{PLAN}",
        {"recheck_id": [selected]},
    )
    assert [op for op in contract.operations if op[0] == "POST"] == [
        ("POST", f"{ACTION_URL}/nginx/{PLAN}/rechecks", {})
    ] * 3
    assert not contract.errors and not any(contract.counts.values())


def test_lost_recheck_requires_readback_and_stale_read_cannot_cross_actions(browser):
    contract = Contract()
    page = open_report(browser, contract)
    open_dialog(page)
    picker = page.locator("#handoff-action")
    expect(picker.locator("option")).to_have_count(4)
    contract.hold_history = True
    picker.select_option("nginx/" + PLAN)
    expect(page.locator("#handoff-action-status")).to_contain_text("正在读取")
    picker.select_option("nginx/" + RESTORE)
    expect(page.locator("#handoff-action-status")).to_contain_text("暂不能运行")
    contract.release()
    expect(page.locator("#handoff-action-run")).to_be_disabled()
    picker.select_option("container_restart/" + PLAN)
    expect(page.locator("#handoff-action-run")).to_be_enabled()
    contract.drop = True
    page.locator("#handoff-action-run").click()
    expect(page.locator("#handoff-dialog-error")).to_contain_text("本次复验结果待核对")
    expect(page.locator("#handoff-action-run")).to_be_disabled()
    assert len([op for op in contract.operations if op[0] == "POST"]) == 1
    page.locator("#handoff-action-refresh").click()
    expect(page.locator("#handoff-action-status")).to_have_text("当前复验 · 复验未通过")
    assert len([op for op in contract.operations if op[0] == "POST"]) == 1
    page.locator("#handoff-cancel").click()
    page.locator(f'[data-report-id="{OTHER}"]').click()
    expect(page.locator("#report-title")).to_have_text("Report B")
    open_dialog(page)
    expect(picker).to_be_hidden()
    assert not contract.errors and not any(contract.counts.values())
