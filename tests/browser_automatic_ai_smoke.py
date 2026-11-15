"""Synthetic automatic AI observation and alert acknowledgement browser contracts.

Run: uv run python tests/browser_automatic_ai_smoke.py --browser chromium
All API traffic is intercepted. No model, SSH, scanner, patch or rearm is contacted.
"""

import argparse
import copy
import json
import re
from contextlib import suppress
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from browser_automatic_smoke import JOB, WIDTHS, refresh, release, wait_pending
from browser_automatic_smoke import Contract as AutomaticContract
from browser_automatic_smoke import safe as automatic_safe
from browser_platform_smoke import static_console
from browser_remediation_smoke import NOW, stamp
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

UNTRUSTED = '<img src=x onerror="window.automaticAIInjection=true">'
ACK = re.compile(r"/api/automatic/ai/alerts/([0-9a-f]{64})/ack")


def request_fixture(index, status):
    return {
        "request_key": f"{index:064x}",
        "host_id": "synthetic-a",
        "candidate_id": f"{index + 10:064x}",
        "analysis_id": f"{index:032x}",
        "status": status,
        "created_at": stamp(-60),
        "updated_at": stamp(-10),
        "deadline_at": stamp(60),
    }


def alert_fixture(index, kind):
    return {
        "id": f"{index:064x}",
        "host_id": "synthetic-a",
        "event_key": f"synthetic-event-{index}",
        "kind": kind,
        "detail": f"合成告警 {index}：" + UNTRUSTED,
        "request_key": f"{index:064x}",
        "candidate_id": f"{index + 10:064x}",
        "job_id": JOB if kind.startswith("repair_") else None,
        "acknowledged": False,
        "acknowledged_at": None,
        "created_at": stamp(-30),
        "updated_at": stamp(-30),
    }


class Contract(AutomaticContract):
    def __init__(self, base_url, *, ai_supported=True, ai_present=True, ai_enabled=True):
        super().__init__(base_url)
        self.ai_supported = ai_supported
        self.ai_present = ai_present
        self.ai_enabled = ai_enabled
        self.ai_requests = [
            request_fixture(1, "failed"),
            request_fixture(2, "unknown"),
            request_fixture(3, "completed"),
        ]
        self.ai_alerts = [
            alert_fixture(index, kind)
            for index, kind in enumerate(
                (
                    "analysis_failed",
                    "analysis_unknown",
                    "no_proposal",
                    "analysis_completed",
                    "plan_ready",
                    "repair_verified",
                ),
                1,
            )
        ]
        self.acknowledgements = []
        self.ack_hold = False
        self.ack_pending = []
        self.fail_ack = False

    def status(self):
        value = super().status()
        if self.ai_present:
            value["ai"] = {
                "enabled": self.ai_enabled,
                "policy": {"max_analyses_per_day": 2, "max_total_analyses": 5},
                "requests": copy.deepcopy(self.ai_requests),
                "alerts": copy.deepcopy(self.ai_alerts),
            }
        return value

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if request.url.startswith(self.base_url + "/") and path == "/api/capabilities":
            self.requests.append((request.method, path))
            if request.method != "GET" or request.headers.get("authorization") != "Bearer " + TOKEN:
                self.failures.append("AI capability read lacked authenticated GET")
            capabilities = {
                "mode": "read_only",
                "model_configured": True,
                "model_name": "synthetic-compatible-model",
                "ssh_hosts": 0,
                "automation_modes": True,
                "vulnerability_remediation": True,
                "automatic_repair": True,
                "vulnerability_watch": False,
                "security_observation": False,
            }
            if self.ai_supported is not None:
                capabilities["automatic_ai"] = self.ai_supported
            self.fulfill(route, capabilities)
            return
        ack = ACK.fullmatch(path)
        if request.url.startswith(self.base_url + "/") and ack:
            self.requests.append((request.method, path))
            if (
                request.method != "POST"
                or request.headers.get("authorization") != "Bearer " + TOKEN
                or request.post_data not in (None, "")
            ):
                self.failures.append("Acknowledgement must only POST the original alert identity")
            self.acknowledgements.append(ack[1])
            found = next((value for value in self.ai_alerts if value["id"] == ack[1]), None)
            if found is None:
                self.failures.append("Acknowledgement changed the original alert identity")
                self.fulfill(route, {"detail": "Unknown synthetic alert"}, 404)
                return
            if self.fail_ack:
                self.fulfill(route, {"detail": "合成已阅存储失败"}, 503)
                return
            found.update(acknowledged=True, acknowledged_at=stamp(), updated_at=stamp())
            body = copy.deepcopy(found)
            if self.ack_hold:
                self.ack_pending.append((route, body, 200))
            else:
                self.fulfill(route, body)
            return
        super().route(route)


def new_case(browser, base_url, *, ignore_abort=False, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.clock.install(time=NOW)
    if ignore_abort:
        page.add_init_script(
            "const nativeFetch=window.fetch;window.automaticAISettled=0;"
            "window.fetch=(input,options={})=>"
            "nativeFetch.call(window,input,{...options,signal:undefined}).then(response=>{"
            "if(String(input).startsWith('/api/automatic/'))queueMicrotask(()=>"
            "queueMicrotask(()=>window.automaticAISettled++));return response;});"
        )
    contract = Contract(base_url, **options)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    page.route("**/*", contract.route)
    login(page, base_url)
    expect(page.locator("#automation-mode-select")).to_be_enabled()
    page.locator("#remediation-nav").click()
    expect(page.locator(".automatic-repair-host")).to_have_count(2)
    expect(page.locator("#refresh-automatic-repair")).to_be_enabled()
    return context, page, contract


def safe(page, contract):
    automatic_safe(page, contract)
    assert page.evaluate("window.automaticAIInjection===undefined")
    expect(page.locator("#automatic-ai-section img")).to_have_count(0)
    expect(page.locator("#automatic-ai-section a")).to_have_count(0)
    writes = [(method, path) for method, path in contract.requests if method != "GET"]
    assert writes == [
        ("POST", f"/api/automatic/ai/alerts/{identifier}/ack")
        for identifier in contract.acknowledgements
    ]


def unchanged_authority(contract):
    return copy.deepcopy(
        (
            contract.ai_requests,
            contract.auto_jobs,
            contract.grants,
            contract.latch,
            contract.quota,
            contract.mode,
            contract.revision,
        )
    )


def check_enabled_and_layout(browser, base_url, screenshots):
    context, page, contract = new_case(browser, base_url)
    try:
        expect(page.locator("#automatic-ai-section")).to_be_visible()
        expect(page.locator("#automatic-ai-summary")).to_contain_text("已配置自动 AI 分析许可")
        expect(page.locator("#automatic-ai-summary")).to_contain_text("每日上限 2")
        expect(page.locator("#automatic-ai-summary")).to_contain_text("本次授权上限 5")
        expect(page.locator("#automatic-ai-requests > article")).to_have_count(3)
        expect(page.locator("#automatic-ai-alerts > article")).to_have_count(6)
        expect(page.locator("#automatic-ai-section")).to_contain_text("失败或未知记录不会自动重发")
        before = unchanged_authority(contract)
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"automatic-ai-{width}.png"), full_page=True)
        assert unchanged_authority(contract) == before and not contract.acknowledgements
        safe(page, contract)
    finally:
        context.close()


def check_disabled_and_legacy(browser, base_url):
    for options, visible in (
        ({"ai_enabled": False}, True),
        ({"ai_supported": False}, False),
        ({"ai_supported": None}, False),
        ({"ai_present": False}, False),
    ):
        context, page, contract = new_case(browser, base_url, **options)
        try:
            section = page.locator("#automatic-ai-section")
            if visible:
                expect(section).to_be_visible()
                expect(page.locator("#automatic-ai-summary")).to_contain_text("自动 AI 分析未启用")
                expect(page.locator("#automatic-ai-requests")).to_contain_text("模型结果未知")
            else:
                expect(section).not_to_be_visible()
                for identifier in (
                    "automatic-ai-summary",
                    "automatic-ai-requests",
                    "automatic-ai-alerts",
                ):
                    expect(page.locator("#" + identifier)).to_have_text("")
            safe(page, contract)
        finally:
            context.close()


def check_status_labels_and_untrusted_text(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        requests = page.locator("#automatic-ai-requests")
        for text in ("模型分析未完成", "模型结果未知 · 只查原记录", "模型分析已返回"):
            expect(requests).to_contain_text(text)
        alerts = page.locator("#automatic-ai-alerts > article")
        labels = (
            "模型分析被阻断",
            "模型结果未知",
            "没有可执行提案",
            "AI提案已核验",
            "原生计划已核验",
            "修复覆盖项验证通过",
        )
        for index, label in enumerate(labels):
            expect(alerts.nth(index).locator("strong")).to_have_text(label)
            expect(alerts.nth(index)).to_contain_text(UNTRUSTED)
        expect(alerts.nth(3)).not_to_contain_text("原生计划已核验")
        expect(alerts.nth(4)).not_to_contain_text("AI提案已核验")
        expect(alerts.last).to_contain_text(JOB)
        before = unchanged_authority(contract)
        refresh(page)
        page.clock.fast_forward(30001)
        expect(page.locator("#refresh-automatic-repair")).to_be_enabled()
        assert unchanged_authority(contract) == before and not contract.acknowledgements
        safe(page, contract)
    finally:
        context.close()


def check_ack_only_records_original_alert(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.latch = {
            "host_id": "synthetic-a",
            "job_id": JOB,
            "reason": "合成原任务未知，暂停保留。",
            "latched_at": stamp(-5),
        }
        contract.host_state = "latched"
        contract.auto_jobs = [
            {
                "host_id": "synthetic-a",
                "job_id": JOB,
                "status": "unknown",
                "updated_at": stamp(-5),
            }
        ]
        refresh(page)
        before = unchanged_authority(contract)
        reads = len(contract.auto_reads)
        item = page.locator("#automatic-ai-alerts > article").nth(1)
        identifier = contract.ai_alerts[1]["id"]
        item.get_by_role("button", name="标记已阅", exact=True).click()
        expect(item).to_contain_text("已阅")
        expect(item.get_by_role("button")).to_have_count(0)
        assert contract.acknowledgements == [identifier] and len(contract.auto_reads) > reads
        assert unchanged_authority(contract) == before
        expect(page.locator("#automatic-repair-hosts")).to_contain_text(JOB)
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("持续暂停，保留原任务")
        refresh(page)
        assert contract.acknowledgements == [identifier]
        assert unchanged_authority(contract) == before
        safe(page, contract)
    finally:
        context.close()


def check_failed_status_and_ack_are_not_new_analysis(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        before = unchanged_authority(contract)
        contract.fail_status = True
        refresh(page)
        expect(page.locator("#automatic-ai-summary")).to_contain_text("状态待核实")
        for button in page.locator("#automatic-ai-alerts button").all():
            expect(button).to_be_disabled()
        assert not contract.acknowledgements
        contract.fail_status = False
        refresh(page)
        contract.fail_ack = True
        item = page.locator("#automatic-ai-alerts > article").first
        item.get_by_role("button", name="标记已阅", exact=True).click()
        expect(page.locator("#automatic-repair-error")).to_contain_text("告警已阅状态未能保存")
        expect(item.locator("span")).to_have_count(0)
        identifier = contract.ai_alerts[0]["id"]
        assert contract.acknowledgements == [identifier]
        page.clock.fast_forward(30001)
        expect(page.locator("#automatic-repair-error")).not_to_be_visible()
        assert contract.acknowledgements == [identifier] and unchanged_authority(contract) == before
        safe(page, contract)
    finally:
        context.close()


def release_ack(contract):
    contract.ack_hold = False
    pending, contract.ack_pending = contract.ack_pending, []
    for route, body, status in pending:
        with suppress(Error):
            contract.fulfill(route, body, status)


def check_late_logout(browser, base_url):
    for hold_ack in (False, True):
        context, page, contract = new_case(browser, base_url, ignore_abort=True)
        try:
            before = unchanged_authority(contract)
            if hold_ack:
                contract.ack_hold = True
                page.locator("#automatic-ai-alerts button").first.click()
                deadline = monotonic() + 5
                while not contract.ack_pending and monotonic() < deadline:
                    page.wait_for_timeout(20)
                assert contract.ack_pending, "Synthetic original alert acknowledgement was not held"
            else:
                contract.auto_hold = True
                page.locator("#refresh-automatic-repair").click()
                wait_pending(page, contract)
            settled = page.evaluate("window.automaticAISettled")
            reads = len(contract.auto_reads)
            page.locator("#logout-button").click()
            release_ack(contract) if hold_ack else release(contract)
            page.wait_for_function("before=>window.automaticAISettled>before", arg=settled)
            expect(page.locator("#automatic-ai-section")).not_to_be_visible()
            for identifier in (
                "automatic-ai-summary",
                "automatic-ai-requests",
                "automatic-ai-alerts",
            ):
                expect(page.locator("#" + identifier)).to_have_text("")
            page.clock.fast_forward(60001)
            assert len(contract.auto_reads) == reads and unchanged_authority(contract) == before
            assert len(contract.acknowledgements) == int(hold_ack)
            safe(page, contract)
        finally:
            release(contract)
            release_ack(contract)
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
            check_enabled_and_layout(browser, base_url, args.screenshots)
            check_disabled_and_legacy(browser, base_url)
            check_status_labels_and_untrusted_text(browser, base_url)
            check_ack_only_records_original_alert(browser, base_url)
            check_failed_status_and_ack_are_not_new_analysis(browser, base_url)
            check_late_logout(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_automatic_ai_case_groups": 6,
                        "viewport_widths": list(WIDTHS),
                        "real_remote_or_model_calls": False,
                        "analysis_plan_install_rearm_requests": 0,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
