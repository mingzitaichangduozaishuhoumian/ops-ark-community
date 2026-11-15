"""Render only closed Compose changes in the existing baseline panel."""

from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import TOKEN
from playwright.sync_api import expect
from test_browser_action_handoff import OTHER, REPORT, Contract, browser, open_report  # noqa: F401

from opsark.compose_generation import GenerationComparison


class GenerationContract(Contract):
    def __init__(self, outcome):
        super().__init__()
        self.outcome = outcome
        self.reads = 0

    def report(self, report_id):
        value = super().report(report_id)
        if report_id == REPORT:
            value.update(
                scenario="container_restart",
                comparison={"baseline_report_id": OTHER, "status": "compared"},
            )
        return value

    def route(self, route):
        path = urlsplit(route.request.url).path
        if not route.request.url.startswith(self.base + "/"):
            return super().route(route)
        if path == "/api/capabilities":
            return self.reply(route, {"mode": "read_only", "compose_generation": True})
        if path == f"/api/reports/{REPORT}/compose-generation":
            assert route.request.method == "GET" and route.request.post_data is None
            assert route.request.headers["authorization"] == "Bearer " + TOKEN
            self.reads += 1
            return self.reply(route, self.outcome)
        return super().route(route)


@pytest.mark.parametrize("mode", ["observed", "unavailable", "foreign_field"])
def test_generation_view_keeps_fixed_results_and_respects_report_navigation(browser, mode):  # noqa: F811
    outcome = GenerationComparison().model_dump()
    if mode != "unavailable":
        outcome.update(status="observed", container="changed", image="unchanged")
    if mode == "foreign_field":
        outcome["unapproved"] = "synthetic-private-identifier"
    contract = GenerationContract(outcome)
    page = open_report(browser, contract, width=390)
    try:
        panel = page.locator("#baseline-section")
        action = panel.get_by_role("button", name="查看容器与 Compose 配置变化")
        expect(action).to_be_visible()
        assert contract.reads == 0
        action.click()
        result = panel.get_by_role("status")
        if mode == "observed":
            for label in ("容器实例", "有变化", "未观察到变化", "证据不足", "操作者未知"):
                expect(result).to_contain_text(label)
        elif mode == "unavailable":
            expect(result).to_contain_text("缺少同一登记范围内可比较的两次观测")
        else:
            expect(result).to_contain_text("暂时无法读取容器变化记录")
        assert contract.reads == 1
        expect(result).not_to_contain_text("synthetic-private-identifier")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.locator(f'[data-report-id="{OTHER}"]').click()
        expect(page.locator("#report-title")).to_have_text("Report B")
        expect(action).to_have_count(0)
        assert not contract.errors and contract.counts["external_requests"] == 0
    finally:
        page.close()
