"""Synthetic Web evidence and AI consent contracts; never uses real credentials."""

import argparse
import json
from contextlib import suppress
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from browser_platform_smoke import static_console
from browser_security_smoke import TOKEN, Contract, login, stamp
from playwright.sync_api import Error, expect, sync_playwright

UNTRUSTED = '<img src=x onerror="window.webSecurityInjection=true">'


def web_alert(identifier, *, trust="forwarded_ignored", aggregate=False):
    host = "synthetic-b" if trust == "unresolved_proxy" else "synthetic-a"
    events = []
    for index in range(5):
        events.append(
            {
                "id": f"{index + 1000:064x}",
                "kind": "web_request",
                "occurred_at": stamp(-70 + index),
                "origin": "controlled_web_probe",
                "site_id": "lab-site",
                "source_ip": None if trust == "unresolved_proxy" else "192.0.2.44",
                "peer_ip": "192.0.2.44",
                "source_trust": trust,
                "method": "GET",
                "status": 404,
                "path_class": [
                    "secret_probe",
                    "repo_probe",
                    "cms_probe",
                    "admin_probe",
                    "traversal_probe",
                ][index],
                "client_class": "declared_crawler",
                "request_time_ms": 10,
                "bytes_sent": 20,
                "expected_error": False,
                "journal_cursor": "synthetic-web-cursor-" + str(index),
                "raw_uri": "/tokenized-private-path?token=not-for-display",
                "user_agent": "not-for-display-raw-agent",
            }
        )
    alert = {
        "id": identifier,
        "host_id": host,
        "scope_hash": "d" * 64,
        "channel": "web",
        "kind": "web_error_burst" if aggregate else "web_scan",
        "severity": "warning",
        "origin": "controlled_web_probe",
        "site_id": "lab-site",
        "source_trust": "site_aggregate" if aggregate else trust,
        "source_ip": None if aggregate or trust == "unresolved_proxy" else "192.0.2.44",
        "title": "Web 合成实验告警",
        "detail": UNTRUSTED,
        "first_seen": stamp(-70),
        "last_seen": stamp(-5),
        "unique_event_count": 5,
        "current_window_count": 5,
        "event_ids": [e["id"] for e in events],
        "observation_id": "web-observation",
        "status": "open",
        "notification_count": 1,
        "last_notified_at": stamp(-5),
        "events": events,
        "observation": {
            "id": "web-observation",
            "status": "complete",
            "gaps": [],
            "collected_at": stamp(),
            "window_started_at": stamp(-900),
            "window_ended_at": stamp(),
        },
    }
    if aggregate:
        alert.update(
            matching_event_count=12,
            observed_request_count=18,
            window_seconds=300,
            coverage_status="complete",
            metric_basis="complete_snapshot_sample",
            evidence_retained=True,
        )
    return alert


class WebContract(Contract):
    def __init__(self, base_url, *, model=False):
        super().__init__(base_url)
        self.model = model
        self.alerts = {
            "web-direct": web_alert("web-direct"),
            "web-proxy": web_alert("web-proxy", trust="unresolved_proxy"),
            "web-aggregate": web_alert("web-aggregate", aggregate=True),
        }
        self.previews = []
        self.sent = []
        self.provider_calls = 0
        self.hold_preview = False
        self.hold_analysis = False
        self.ai_pending = []
        self.reject_digest = False

    def status(self):
        value = super().status()
        for host in value["hosts"]:
            host["channels"] = {
                "ssh": {
                    "scope_hash": "f" * 64,
                    "status": "ok",
                    "last_success": stamp(),
                    "detail": "SSH 合成观察",
                },
                "web": {
                    "scope_hash": "d" * 64,
                    "status": "ok",
                    "last_success": stamp(),
                    "detail": "Web 合成观察",
                },
            }
        return value

    def preview(self, identifier):
        return {
            "input": {
                "target_ref": "target-1",
                "events": [
                    {
                        "id": self.alerts[identifier]["events"][0]["id"],
                        "site_ref": "site-1",
                        "source_ref": "source-1",
                        "path_class": "secret_probe",
                    }
                ],
                "constraints": {"actions_executable": False},
            },
            "input_digest": "2" * 64 if self.reject_digest else "1" * 64,
        }

    def analysis(self, identifier):
        return {
            "status": "completed",
            "summary": UNTRUSTED,
            "uncertainty": ["合成分类证据不能确认真实攻击。"],
            "evidence_ids": [self.alerts[identifier]["events"][0]["id"]],
            "recommendations": [
                {
                    "kind": "review_origin_protection",
                    "rationale": "合成建议，需管理员复核。",
                    "evidence_ids": [self.alerts[identifier]["events"][0]["id"]],
                }
            ],
            "actions_executable": False,
            "input_digest": "1" * 64,
            "model": "synthetic-model",
        }

    def route(self, route):
        request = route.request
        if not request.url.startswith(self.base_url + "/"):
            self.failures.append("Unexpected external browser destination")
            route.abort()
            return
        path = urlsplit(request.url).path
        if (
            path.startswith("/api/")
            and path != "/api/status"
            and request.headers.get("authorization") != "Bearer " + TOKEN
        ):
            self.failures.append("Missing authentication on Web/AI contract request")
        if path == "/api/capabilities":
            self.requests.append((request.method, path))
            self.fulfill(
                route,
                {
                    "mode": "read_only",
                    "security_observation": True,
                    "security_web": True,
                    "security_ai": True,
                    "model_configured": self.model,
                    "model_name": "synthetic-model" if self.model else None,
                    "ssh_hosts": 0,
                },
            )
            return
        for identifier in self.alerts:
            prefix = "/api/security/alerts/" + identifier
            if path == prefix + "/analysis-input":
                self.requests.append((request.method, path))
                self.previews.append(identifier)
                if self.hold_preview:
                    self.ai_pending.append((route, self.preview(identifier)))
                    return
                self.fulfill(route, self.preview(identifier))
                return
            if path == prefix + "/analyze":
                self.requests.append((request.method, path))
                self.sent.append((identifier, request.post_data_json))
                if request.method != "POST" or request.post_data_json != {
                    "confirm_send": True,
                    "expected_input_digest": "1" * 64,
                }:
                    self.failures.append("Unexpected analysis authority or consent body")
                if self.reject_digest:
                    self.fulfill(route, {"detail": "分类证据已变化，请重新确认。"}, 409)
                    return
                self.provider_calls += 1
                result = self.analysis(identifier)
                self.alerts[identifier]["analysis"] = result
                if self.hold_analysis:
                    self.ai_pending.append((route, result))
                    return
                self.fulfill(route, result)
                return
        super().route(route)


def new_case(browser, base_url, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    contract = WebContract(base_url, **options)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.route("**/*", contract.route)
    return context, page, contract, errors


def select(page, identifier):
    page.locator('[data-security-alert="' + identifier + '"]').click()
    expect(page.locator("#security-alert-detail")).to_contain_text("Web 合成实验告警")


def check_web_evidence(browser, base_url, screenshots):
    context, page, contract, errors = new_case(browser, base_url)
    try:
        login(page, base_url)
        page.locator('button[data-view="security"]').click()
        expect(page.locator(".security-host-card")).to_have_count(2)
        expect(page.locator('[data-security-channel="web"]')).to_have_count(2)
        select(page, "web-direct")
        expect(page.locator("#security-alert-detail")).to_contain_text("Web 实验演练")
        page.locator(".security-event summary").first.click()
        expect(page.locator(".security-event").first).to_contain_text("转发头不可信")
        expect(page.locator(".security-event").first).to_contain_text("自称爬虫（未验证）")
        expect(page.locator("#request-security-ai")).to_be_disabled()
        expect(page.locator("#security-ai-section")).to_contain_text("待配置")
        assert not contract.previews and not contract.sent
        assert "tokenized-private-path" not in page.locator("#security-alert-detail").inner_text()
        assert (
            "not-for-display-raw-agent" not in page.locator("#security-alert-detail").inner_text()
        )
        select(page, "web-proxy")
        expect(page.locator("#security-alert-detail")).to_contain_text("不能据此封禁")
        select(page, "web-aggregate")
        expect(page.locator("#security-alert-detail")).to_contain_text("站点聚合 · 不归因单个来源")
        expect(page.locator("#security-alert-detail")).to_contain_text("告警观察样本 18 条")
        expect(page.locator("#security-alert-detail")).to_contain_text("规则匹配 12 条")
        expect(page.locator("#security-alert-detail img")).to_have_count(0)
        assert page.evaluate("window.webSecurityInjection === undefined")
        for width in (1440, 1024, 768, 390, 320):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"web-security-{width}.png"), full_page=True)
        assert not errors and not contract.failures, (errors, contract.failures)
    finally:
        context.close()


def open_ai(page):
    page.locator("#request-security-ai").click()
    expect(page.locator("#security-ai-dialog")).to_be_visible()
    expect(page.locator("#security-ai-confirm")).to_be_enabled()


def check_ai_consent(browser, base_url):
    context, page, contract, errors = new_case(browser, base_url, model=True)
    try:
        login(page, base_url)
        page.locator('button[data-view="security"]').click()
        select(page, "web-direct")
        open_ai(page)
        expect(page.locator("#security-ai-send")).to_be_disabled()
        assert contract.provider_calls == 0
        assert "target-1" in page.locator("#security-ai-preview").text_content()
        page.locator("#security-ai-confirm").check()
        page.locator("#security-ai-send").click()
        expect(page.locator("#security-ai-dialog")).not_to_be_visible()
        expect(page.locator("#security-ai-section")).to_contain_text("没有执行封禁")
        expect(page.locator("#security-ai-section")).to_contain_text(UNTRUSTED)
        expect(page.locator("#security-ai-section img")).to_have_count(0)
        assert contract.provider_calls == 1
        page.locator("#security-ai-section .evidence-link").first.click()
        expect(page.locator(".security-event").first).to_have_attribute("open", "")
        open_ai(page)
        contract.reject_digest = True
        page.locator("#security-ai-confirm").check()
        page.locator("#security-ai-send").click()
        expect(page.locator("#security-ai-dialog-error")).to_contain_text("重新读取")
        expect(page.locator("#security-ai-send")).to_be_disabled()
        expect(page.locator("#security-ai-confirm")).to_be_disabled()
        assert contract.provider_calls == 1
        page.locator("#security-ai-cancel").click()
        assert not errors and not contract.failures, (errors, contract.failures)
    finally:
        context.close()


def release_pending(contract):
    for route, body in contract.ai_pending:
        with suppress(Error):
            contract.fulfill(route, body)
    contract.ai_pending.clear()


def wait_pending(page, contract):
    deadline = monotonic() + 3
    while not contract.ai_pending and monotonic() < deadline:
        page.wait_for_timeout(10)
    assert contract.ai_pending, "Expected an actual held request before race steering"


def check_late_preview_and_logout(browser, base_url):
    context, page, contract, errors = new_case(browser, base_url, model=True)
    try:
        login(page, base_url)
        page.locator('button[data-view="security"]').click()
        select(page, "web-direct")
        contract.hold_preview = True
        page.locator("#request-security-ai").click()
        expect(page.locator("#security-ai-dialog")).to_be_visible()
        page.wait_for_function(
            "document.querySelector('#security-ai-preview').textContent.includes('正在读取')"
        )
        wait_pending(page, contract)
        page.evaluate("document.querySelector('[data-security-alert=web-proxy]').click()")
        expect(page.locator("#security-ai-dialog")).not_to_be_visible()
        release_pending(contract)
        expect(page.locator("#security-alert-detail")).to_contain_text("不能据此封禁")
        assert contract.provider_calls == 0
        contract.hold_preview = False
        open_ai(page)
        contract.hold_analysis = True
        page.locator("#security-ai-confirm").check()
        page.locator("#security-ai-send").click()
        page.wait_for_function(
            "document.querySelector('#security-ai-send').textContent.includes('正在生成')"
        )
        wait_pending(page, contract)
        page.evaluate("document.querySelector('#logout-button').click()")
        expect(page.locator("#login-screen")).to_be_visible()
        release_pending(contract)
        expect(page.locator("#security-alert-detail")).to_have_text("")
        expect(page.locator("#security-ai-preview")).to_have_text("")
        assert not errors and not contract.failures, (errors, contract.failures)
    finally:
        context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with static_console() as base_url, sync_playwright() as p:
        browser = getattr(p, args.browser).launch(headless=True)
        try:
            check_web_evidence(browser, base_url, args.screenshots)
            check_ai_consent(browser, base_url)
            check_late_preview_and_logout(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_web_and_ai_cases": 3,
                        "viewport_widths": [1440, 1024, 768, 390, 320],
                        "real_remote_or_model_calls": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
