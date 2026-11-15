"""Synthetic full-browser report UI; no server, SSH, model, clipboard or shell execution."""

import json
from copy import deepcopy
from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import TOKEN, ComposeContract
from playwright.sync_api import expect, sync_playwright
from test_disk_reclaim import check, collection, host

from opsark.diagnostics import diagnose


class Contract(ComposeContract):
    def __init__(self, mutation=None):
        super().__init__()
        self.base = "http://127.0.0.1:18491"
        self.report = diagnose("disk", host(), collection(check())).model_dump(mode="json")
        self.report["source"] = self.report["target"]["source"] = "ssh"
        for item in self.report["evidence"]:
            item["source"] = "ssh"
        if mutation:
            mutation(self.report)
        self.report_calls = []

    def route(self, route):
        path = urlsplit(route.request.url).path
        if route.request.url.startswith(self.base + "/") and path in {
            "/api/reports",
            "/api/reports/" + self.report["id"],
        }:
            assert route.request.method == "GET"
            assert route.request.headers.get("authorization") == "Bearer " + TOKEN
            self.report_calls.append(path)
            route.fulfill(
                content_type="application/json",
                body=json.dumps([self.report] if path == "/api/reports" else self.report),
            )
        else:
            super().route(route)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(headless=True)
        yield instance
        instance.close()


def open_report(browser, contract, width=1440):
    context = browser.new_context(
        viewport={"width": width, "height": 1000}, service_workers="block"
    )
    page = context.new_page()
    page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
    page.route("**/*", contract.route)
    page.goto(contract.base)
    page.wait_for_load_state("networkidle")
    page.locator("#token-input").fill(TOKEN)
    page.locator("#login-button").click()
    expect(page.locator("#report-content")).to_be_visible()
    page.locator('[data-tab="evidence"]').click()
    page.locator('[data-evidence-id="E-DISK-RECLAIM"] summary').click()
    return context, page


@pytest.mark.parametrize("width", [320, 1440])
def test_report_offers_copyable_exact_local_root_locator_without_any_execution(browser, width):
    contract = Contract()
    context, page = open_report(browser, contract, width)
    try:
        panel = page.locator("[data-disk-local-locator]")
        expect(panel).to_be_visible()
        expect(panel).to_contain_text("不要上传定位结果")
        inputs = panel.locator("[data-disk-locate-command]")
        expect(inputs).to_have_count(5)
        values = inputs.evaluate_all("items=>items.map(item=>item.value)")
        assert all(
            value.startswith("/usr/local/libexec/opsark-disk-reclaim --locate-ref ")
            and "--expected-scope-sha256" in value
            and "--expected-snapshot-sha256" in value
            for value in values
        )
        before = deepcopy(contract.calls)
        panel.get_by_role("button", name="选中本地定位命令").first.click()
        assert inputs.first.evaluate(
            "item=>item.selectionStart===0 && item.selectionEnd===item.value.length"
        )
        assert contract.calls == before
        assert "/srv/registered" not in page.locator("body").inner_text()
        assert "locations" not in page.locator("body").inner_text()
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not contract.errors
        assert all(
            not contract.counts[key]
            for key in ("external_requests", "unexpected_routes", "forbidden_writes")
        )
    finally:
        context.close()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update({"source": "replay"}),
        lambda report: report.update({"ai_egress_block_reason": "unclassified_payload"}),
        lambda report: report["target"].update({"disk_reclaim_scope_digest": "0" * 64}),
        lambda report: report["evidence"][-1].update({"truncated": True}),
        lambda report: report["evidence"][-1].update({"output": "unclassified"}),
    ],
)
def test_partial_unbound_replay_or_blocked_reports_never_offer_locator(browser, mutation):
    contract = Contract(mutation)
    context, page = open_report(browser, contract)
    try:
        expect(page.locator("[data-disk-local-locator]")).to_have_count(0)
        assert not contract.errors
    finally:
        context.close()


@pytest.mark.parametrize("width", [320, 1440])
def test_baseline_ui_points_to_class_and_directory_combination_without_file_tracking(
    browser, tmp_path, width
):
    from test_disk_reclaim_baselines import filesystem, report

    from opsark.baselines import BaselineStore, compare

    baseline = BaselineStore(tmp_path / "history.sqlite3").save(report())
    current = report(filesystem(grow=True))
    current.comparison = compare(current, baseline)
    contract = Contract()
    contract.report = current.model_dump(mode="json")
    context, page = open_report(browser, contract, width)
    try:
        page.locator('[data-tab="diagnosis"]').click()
        panel = page.locator("#baseline-section")
        expect(panel).to_contain_text("登记目录组合 directory-1 + directory-3")
        expect(panel).to_contain_text("组合只计一次")
        expect(panel).to_contain_text("不同汇总层次，不能再相加")
        expect(panel).to_contain_text("已分配字节增加 2048")
        expect(panel).to_contain_text("业务数据（排除清理）")
        expect(panel).to_contain_text("不连续追踪单文件")
        assert "/srv/" not in page.locator("body").inner_text()
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not contract.errors
    finally:
        context.close()


def test_unknown_allocation_metric_hides_whole_comparison_in_browser(browser):
    contract = Contract(
        lambda value: value.update(
            {
                "comparison": {
                    "status": "compared",
                    "changes": [
                        {
                            "field": "disk_scope.total.allocated_bytes",
                            "before": "512",
                            "after": "1024",
                        },
                        {"field": "disk_scope.unknown", "before": "0", "after": "512"},
                    ],
                    "missing": [],
                    "purpose": "observation_only",
                    "restore_capable": False,
                }
            }
        )
    )
    context, page = open_report(browser, contract)
    try:
        page.locator('[data-tab="diagnosis"]').click()
        panel = page.locator("#baseline-section")
        expect(panel).to_contain_text("整份对照未展示")
        expect(panel.locator(".baseline-change")).to_have_count(0)
        assert "disk_scope.unknown" not in panel.inner_text()
    finally:
        context.close()
