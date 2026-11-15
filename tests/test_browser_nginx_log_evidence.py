"""Nginx log-window summaries in real browsers with closed synthetic responses."""

from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import PRIVATE, TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright

REPORT = "log-window-current"
LEGACY = "log-window-legacy"
AT = "2026-11-14T10:00:00.123456Z"


def window(status, reason=None, refused=None, timeout=None):
    return {
        "status": status,
        "reason": reason,
        "observed_at": AT,
        "window_seconds": 900,
        "matching_refused": refused,
        "matching_timeout": timeout,
    }


class Contract(ComposeContract):
    def __init__(self, value, with_row=True):
        super().__init__()
        self.base = "http://127.0.0.1:18558"
        self.value = value
        self.with_row = with_row

    def report(self, report_id):
        current = report_id == REPORT
        evidence = {
            "id": "evidence-log",
            "check_id": "nginx_errors",
            "source": "ssh",
            "target": "fixture",
            "collected_at": AT,
            "status": "ok",
            "output": PRIVATE if current else "Legacy synthetic log",
        }
        rows = [evidence] if self.with_row or not current else []
        report = {
            "id": report_id,
            "host_id": "fixture",
            "host_name": "Synthetic VPS",
            "scenario": "web_502",
            "status": "inconclusive",
            "source": "ssh",
            "created_at": AT,
            "title": "Log window fixture",
            "summary": "Synthetic report",
            "duration_ms": 1,
            "facts": [{"text": "Log evidence reference", "evidence_ids": ["evidence-log"]}]
            if rows
            else [],
            "candidates": [],
            "missing": [],
            "evidence": rows,
            "next_steps": [],
        }
        if current:
            report["nginx_error_window"] = self.value
        return report

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/"):
            return super().route(route)
        if path in {"/api/reports", f"/api/reports/{REPORT}", f"/api/reports/{LEGACY}"}:
            assert request.method == "GET"
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            value = (
                [self.report(REPORT), self.report(LEGACY)]
                if path == "/api/reports"
                else self.report(path.rsplit("/", 1)[1])
            )
            return route.fulfill(json=value)
        return super().route(route)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright, launch_fixture_browser(playwright) as instance:
        yield instance


@pytest.fixture
def open_report(browser):
    pages = []

    def open_page(contract):
        page = browser.new_page(service_workers="block")
        pages.append(page)
        page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
        page.route("**/*", contract.route)
        page.goto(contract.base)
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        page.locator(f'#report-list [data-report-id="{REPORT}"]').click()
        expect(page.locator("#report-id")).to_have_text(REPORT)
        return page

    yield open_page
    for page in pages:
        page.close()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (window("permission_denied"), "权限不足"),
        (window("source_missing"), "日志文件缺失"),
        (
            window("observed", refused=0, timeout=0),
            "未观察到可识别的登记站点上游拒绝连接或超时事件",
        ),
        (window("observed", refused=2, timeout=3), "拒绝连接 2 次，超时 3 次"),
        (window("observed", refused=511, timeout=1), "拒绝连接 511 次，超时 1 次"),
        (window("inconclusive", "coverage_unconfirmed"), "无法确认取样覆盖最近 15 分钟"),
    ],
)
def test_log_window_status_and_counts_stay_bodyless(value, expected, open_report):
    contract = Contract(value)
    page = open_report(contract)
    # Existing diagnostic links must still open their original log evidence row.
    page.get_by_role("button", name="evidence-log ↗").click()
    expect(page.locator('[data-evidence-id="evidence-log"]')).to_have_attribute("open", "")
    summary = page.get_by_role("region", name="Nginx 错误日志窗口")
    expect(summary).to_contain_text(expected)
    expect(summary).to_contain_text("网站健康需要单独核验")
    expect(summary.locator("time")).to_have_attribute("datetime", AT)
    expect(page.locator("#report-panel")).not_to_contain_text(PRIVATE)
    expect(page.locator("#report-panel pre")).to_have_count(0)
    if value["status"] != "observed":
        expect(summary).not_to_contain_text("未观察到")
    assert not contract.errors and not any(contract.counts.values())


def test_bad_new_projection_hides_body_and_preserves_legacy_history(open_report):
    contract = Contract(window("observed", refused=0, timeout=0) | {"raw": PRIVATE})
    page = open_report(contract)
    page.locator("#tab-evidence").click()
    summary = page.get_by_role("region", name="Nginx 错误日志窗口")
    expect(summary).to_contain_text("日志窗口摘要无法核实")
    expect(page.locator("#report-panel")).not_to_contain_text(PRIVATE)
    expect(summary).not_to_contain_text("未观察到")
    page.locator(f'#report-list [data-report-id="{LEGACY}"]').click()
    expect(page.locator("#report-id")).to_have_text(LEGACY)
    page.locator("#tab-evidence").click()
    expect(summary).to_have_count(0)
    page.locator('[data-evidence-id="evidence-log"] summary').click()
    expect(page.locator("#report-panel pre")).to_have_text("Legacy synthetic log")
    assert not contract.errors and not any(contract.counts.values())


def test_window_visible_without_legacy_log_evidence_row(open_report):
    contract = Contract(window("inconclusive", "source_changed"), with_row=False)
    page = open_report(contract)
    page.locator("#tab-evidence").click()
    expect(page.get_by_role("region", name="Nginx 错误日志窗口")).to_contain_text(
        "采集期间日志来源发生变化"
    )
    expect(page.locator("#report-panel pre")).to_have_count(0)
    assert not contract.errors and not any(contract.counts.values())


def test_window_rejects_counts_above_combined_sample_limit(open_report):
    contract = Contract(window("observed", refused=511, timeout=2))
    page = open_report(contract)
    page.locator("#tab-evidence").click()
    summary = page.get_by_role("region", name="Nginx 错误日志窗口")
    expect(summary).to_contain_text("日志窗口摘要无法核实")
    expect(summary).not_to_contain_text("511")
    expect(page.locator("#report-panel")).not_to_contain_text(PRIVATE)
    assert not contract.errors and not any(contract.counts.values())
