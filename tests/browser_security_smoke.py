"""Synthetic browser contracts for observation, evidence and local acknowledgement.

No server credentials, real SSH targets, model or external notification is used.
Run: uv run python tests/browser_security_smoke.py --browser chromium
"""

import argparse
import copy
import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from browser_platform_smoke import static_console
from playwright.sync_api import Error, expect, sync_playwright

TOKEN = "synthetic-security-browser-token"
UNTRUSTED = '<img src=x onerror="window.securityInjection=true">'


def stamp(offset=0):
    return (datetime.now(UTC) + timedelta(seconds=offset)).isoformat()


def alert_fixture(identifier, origin):
    controlled = origin == "controlled_probe"
    host = "synthetic-b" if controlled else "synthetic-a"
    events = []
    for index in range(5 if controlled else 6):
        events.append(
            {
                "id": f"{index + (100 if controlled else 1):064x}",
                "occurred_at": stamp(-60 + index * 9),
                "origin": origin,
                "kind": "authentication_accepted"
                if not controlled and index == 5
                else "authentication_failed",
                "source_ip": "127.0.0.1" if controlled else "192.0.2.30",
                "method": "publickey",
                "account_type": "invalid" if controlled else "root",
                "unit": "opsark-security-probe.service" if controlled else "ssh.service",
                "journal_cursor": "s=synthetic;" + str(index),
            }
        )
    return {
        "id": identifier,
        "host_id": host,
        "scope_hash": "f" * 64,
        "kind": "repeated_auth_failures" if controlled else "success_after_failures",
        "severity": "warning" if controlled else "high",
        "origin": origin,
        "source_ip": "127.0.0.1" if controlled else "192.0.2.30",
        "title": "合成演练重复失败" if controlled else "失败后出现成功，需核对授权",
        "detail": "仅为合成浏览器契约。" if controlled else UNTRUSTED,
        "first_seen": stamp(-60),
        "last_seen": stamp(-5),
        "unique_event_count": len(events),
        "current_window_count": len(events),
        "event_ids": [item["id"] for item in events],
        "observation_id": "synthetic-observation",
        "status": "open",
        "notification_count": 1,
        "last_notified_at": stamp(-5),
        "events": events,
        "observation": {
            "id": "synthetic-observation",
            "status": "degraded" if controlled else "complete",
            "gaps": ["合成缺口：仅用于浏览器验证。"] if controlled else [],
            "collected_at": stamp(),
            "window_started_at": stamp(-900),
            "window_ended_at": stamp(),
        },
    }


class Contract:
    def __init__(self, base_url, *, supported=True, missing=False):
        self.base_url = base_url
        self.supported = supported
        self.missing = missing
        self.fail_read = False
        self.reject_auth = False
        self.hold_details = False
        self.scope_hash = "f" * 64
        self.pending = []
        self.requests = []
        self.failures = []
        self.alerts = {
            "real-fixture": alert_fixture("real-fixture", "system_ssh"),
            "lab-fixture": alert_fixture("lab-fixture", "controlled_probe"),
        }

    def status(self):
        return {
            "enabled": True,
            "running": True,
            "interval_seconds": 60,
            "window_seconds": 900,
            "threshold": 5,
            "notification_channel": "console",
            "read_only": True,
            "hosts": [
                {
                    "host_id": "synthetic-a",
                    "scope_hash": self.scope_hash,
                    "name": "合成目标 A",
                    "status": "ok",
                    "last_attempt": stamp(),
                    "last_success": stamp(),
                    "next_poll": stamp(60),
                    "detail": "本轮完成，不代表服务器安全。",
                },
                {
                    "host_id": "synthetic-b",
                    "scope_hash": self.scope_hash,
                    "name": "合成目标 B",
                    "status": "stale",
                    "last_attempt": stamp(),
                    "last_success": stamp(-600),
                    "next_poll": stamp(60),
                    "detail": UNTRUSTED,
                },
            ],
        }

    def route(self, route):
        request = route.request
        if not request.url.startswith(self.base_url + "/"):
            self.failures.append("Unexpected external destination")
            route.abort()
            return
        path = urlsplit(request.url).path
        if not path.startswith("/api/"):
            route.continue_()
            return
        self.requests.append((request.method, path))
        if path != "/api/status" and request.headers.get("authorization") != "Bearer " + TOKEN:
            self.failures.append("Missing authentication on protected synthetic API")
        if path.startswith("/api/security/"):
            if self.reject_auth:
                self.fulfill(route, {"detail": "Synthetic authentication failure"}, 401)
                return
            if self.missing:
                self.fulfill(route, {"detail": "Synthetic unsupported endpoint"}, 404)
                return
            if self.fail_read and request.method == "GET":
                self.fulfill(route, {"detail": "Synthetic observation unavailable"}, 503)
                return
            if path == "/api/security/status":
                self.fulfill(route, self.status())
                return
            if path == "/api/security/alerts":
                self.fulfill(
                    route,
                    [
                        {
                            key: value
                            for key, value in alert.items()
                            if key not in {"events", "observation"}
                        }
                        for alert in self.alerts.values()
                    ],
                )
                return
            for identifier, alert in self.alerts.items():
                if path == "/api/security/alerts/" + identifier:
                    if self.hold_details:
                        self.pending.append((route, copy.deepcopy(alert)))
                        return
                    self.fulfill(route, alert)
                    return
                if path == "/api/security/alerts/" + identifier + "/ack":
                    if request.method != "POST" or request.post_data_json != {"acknowledge": True}:
                        self.failures.append("Unexpected acknowledgement request")
                    alert["status"] = "acknowledged"
                    self.fulfill(route, alert)
                    return
        payloads = {
            "/api/status": {"version": "synthetic-security-contract", "requires_auth": True},
            "/api/capabilities": {
                "mode": "read_only",
                "security_observation": self.supported,
                "ssh_hosts": 0,
                "model_configured": False,
            },
            "/api/samples": [],
            "/api/hosts": [],
            "/api/reports": [],
        }
        if path not in payloads:
            self.failures.append("Unexpected synthetic API request: " + path)
        self.fulfill(route, payloads.get(path, {}), 200 if path in payloads else 404)

    @staticmethod
    def fulfill(route, body, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    def read_count(self):
        return sum(path == "/api/security/status" for _, path in self.requests)


def login(page, base_url):
    page.goto(base_url, wait_until="networkidle")
    page.locator("#token-input").fill(TOKEN)
    page.locator("#login-button").click()
    expect(page.locator("#app-shell")).to_be_visible()


def new_case(browser, base_url, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.clock.install()
    contract = Contract(base_url, **options)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    page.route("**/*", contract.route)
    login(page, base_url)
    return context, page, contract


def check_observation(browser, base_url, screenshots):
    context, page, contract = new_case(browser, base_url)
    try:
        expect(page.locator("#security-alert-count")).to_have_text("2")
        page.locator('button[data-view="security"]').click()
        expect(page.locator(".security-host-card")).to_have_count(2)
        expect(page.locator("#security-host-list")).to_contain_text("观察记录已过期")
        expect(page.locator("#security-host-list")).to_contain_text(UNTRUSTED)
        expect(page.locator("#security-alert-detail")).to_contain_text("失败后出现成功")
        expect(page.locator("#security-alert-detail")).to_contain_text(UNTRUSTED)
        expect(page.locator("#security-alert-detail img")).to_have_count(0)
        assert page.evaluate("window.securityInjection === undefined")
        expect(page.locator(".security-event")).to_have_count(6)
        page.locator(".security-event summary").first.click()
        expect(page.locator("#security-alert-detail")).to_contain_text("root 账号")
        expect(page.locator("#ack-security-alert")).to_be_enabled()
        page.locator("#ack-security-alert").click()
        expect(page.locator("#ack-security-alert")).to_have_text("已标记已阅")
        expect(page.locator("#security-alert-count")).to_have_text("1")
        expect(page.locator("#security-alert-detail")).to_contain_text("未证明风险解除")
        expect(page.locator("#security-alert-detail")).to_contain_text("告警证据窗口事件")
        expect(page.locator("#security-alert-detail")).to_contain_text("不表示这些失败仍在发生")
        page.locator('button[data-security-alert="lab-fixture"]').click()
        expect(page.locator("#security-alert-detail")).to_contain_text("演练告警")
        expect(page.locator("#security-alert-detail")).to_contain_text(
            "不能作为真实攻击或入侵的证据"
        )
        expect(page.locator(".security-event")).to_have_count(5)
        page.locator(".security-event summary").first.click()
        page.locator("#refresh-security").click()
        expect(page.locator("#refresh-security")).to_be_enabled()
        expect(page.locator(".security-event").first).to_have_attribute("open", "")
        for width in (1440, 1024, 768, 390, 320):
            page.set_viewport_size({"width": width, "height": 1100})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"security-{width}.png"), full_page=True)
        before = contract.read_count()
        page.clock.fast_forward(15000)
        expect(page.locator("#refresh-security")).to_be_enabled()
        assert contract.read_count() > before, "Visible security view did not refresh"
        page.locator('button[data-view="capabilities"]').click()
        before = contract.read_count()
        page.clock.fast_forward(60000)
        assert contract.read_count() == before, "Hidden security view continued polling"
        page.locator('button[data-view="security"]').click()
        expect(page.locator("#refresh-security")).to_be_enabled()
        page.evaluate(
            "Object.defineProperty(document,'hidden',{configurable:true,value:true});"
            "document.dispatchEvent(new Event('visibilitychange'))"
        )
        before = contract.read_count()
        page.clock.fast_forward(60000)
        assert contract.read_count() == before, "Hidden document continued polling"
        page.evaluate(
            "Object.defineProperty(document,'hidden',{configurable:true,value:false});"
            "document.dispatchEvent(new Event('visibilitychange'))"
        )
        expect(page.locator("#refresh-security")).to_be_enabled()
        contract.scope_hash = "e" * 64
        page.locator("#refresh-security").click()
        expect(page.locator("#security-alert-detail")).to_contain_text("该告警属于历史登记范围")
        contract.fail_read = True
        page.locator("#refresh-security").click()
        expect(page.locator("#security-error")).to_contain_text("历史记录不代表当前覆盖")
        expect(page.locator(".security-alert-button")).to_have_count(2)
        contract.fail_read = False
        contract.reject_auth = True
        page.locator("#refresh-security").click()
        expect(page.locator("#login-screen")).to_be_visible()
        expect(page.locator("#token-input")).to_have_value("")
        expect(page.locator("#security-alert-detail")).to_have_text("")
        before = contract.read_count()
        page.clock.fast_forward(60000)
        assert contract.read_count() == before, "Signed-out page continued polling"
        assert page.evaluate(
            "Object.keys(localStorage).length===0 && Object.keys(sessionStorage).length===0"
        )
        assert not contract.failures, contract.failures
    finally:
        context.close()


def check_late_detail(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        expect(page.locator("#security-alert-count")).to_have_text("2")
        page.locator('button[data-view="security"]').click()
        expect(page.locator("#security-alert-detail")).to_contain_text("失败后出现成功")
        expect(page.locator("#refresh-security")).to_be_enabled()
        contract.hold_details = True
        page.locator('button[data-security-alert="lab-fixture"]').click()
        page.wait_for_function(
            "document.querySelector('#security-alert-detail').textContent.includes('正在读取')"
        )
        assert contract.pending, "No detail response was held for the logout race"
        page.locator("#logout-button").click()
        expect(page.locator("#login-screen")).to_be_visible()
        for route, body in contract.pending:
            with suppress(Error):
                contract.fulfill(route, body)
        expect(page.locator("#security-alert-detail")).to_have_text("")
        expect(page.locator("#security-alert-count")).to_be_hidden()
        assert not contract.failures, contract.failures
    finally:
        context.close()


def check_unsupported(browser, base_url, *, missing):
    context, page, contract = new_case(browser, base_url, supported=missing, missing=missing)
    try:
        page.locator('button[data-view="security"]').click()
        expect(page.locator("#security-monitor-summary")).to_contain_text("当前实例未开放")
        expect(page.locator("#refresh-security")).to_be_disabled()
        if not missing:
            assert contract.read_count() == 0
        before = contract.read_count()
        page.clock.fast_forward(60000)
        assert contract.read_count() == before
        assert not contract.failures, contract.failures
    finally:
        context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with static_console() as base_url, sync_playwright() as playwright:
        browser = getattr(playwright, args.browser).launch(headless=True)
        try:
            check_observation(browser, base_url, args.screenshots)
            check_late_detail(browser, base_url)
            check_unsupported(browser, base_url, missing=False)
            check_unsupported(browser, base_url, missing=True)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_cases": 4,
                        "viewport_widths": [1440, 1024, 768, 390, 320],
                        "real_security_backend_or_ssh_verified": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
