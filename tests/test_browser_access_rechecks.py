"""Exact browser contracts for the report-bound SSH outage recheck."""

from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import PRIVATE, TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright

REPORT = "ssh-outage-fixture"
OTHER = "another-fixture"
HISTORY = f"/api/reports/{REPORT}/access-rechecks"
AT = "2026-11-14T10:00:00Z"
BEFORE = "2026-11-14T09:58:00Z"


class Contract(ComposeContract):
    def __init__(self, *, can_run=True, eligible=True, enabled=True):
        super().__init__()
        self.base = "http://127.0.0.1:18557"
        self.operations = []
        self.rows = []
        self.can_run = can_run
        self.eligible = eligible
        self.enabled = enabled
        self.hold = None
        self.pending = None
        self.drop = False
        self.next = None

    def row(self, external, *, verified=False):
        return {
            "id": f"ar-{len(self.rows) + 1:032x}",
            "report_id": REPORT,
            "finished_at": "2026-11-14T10:01:00Z",
            "management": "verified" if verified else "unavailable",
            "external": external,
            "checks": [{"id": "primary", "status": "passed" if verified else "inconclusive"}],
            "status": {
                "matched": "accepted" if verified else "pending",
                "unreachable": "failed",
                "unavailable": "pending",
            }[external],
        }

    def report(self, report_id):
        return {
            "id": report_id,
            "host_id": "site-a",
            "host_name": "Synthetic Site A",
            "scope_hash": "8" * 64,
            "scenario": "web_502",
            "status": "inconclusive",
            "source": "ssh",
            "created_at": AT,
            "title": "SSH outage report" if report_id == REPORT else "Other report",
            "summary": "Synthetic diagnostic",
            "duration_ms": 1,
            "facts": [],
            "candidates": [],
            "missing": [],
            "evidence": [
                {
                    "id": "evidence-one",
                    "check_id": "connection",
                    "source": "ssh",
                    "collected_at": AT,
                    "status": "error",
                    "exit_code": None,
                    "output": "SSH connection unavailable",
                }
            ]
            if self.eligible and report_id == REPORT
            else [],
            "next_steps": [],
        }

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/api/") or path == "/api/status":
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == "/api/capabilities":
            value = {"mode": "read_only", "access_rechecks": self.enabled}
        elif path == "/api/reports":
            value = [self.report(REPORT), self.report(OTHER)]
        elif path in {f"/api/reports/{REPORT}", f"/api/reports/{OTHER}"}:
            value = self.report(path.rsplit("/", 1)[1])
        elif path == HISTORY and request.method == "GET":
            self.operations.append(("GET", HISTORY, None))
            value = {
                "report_id": REPORT,
                "can_run": self.can_run,
                "last_evidence_at": BEFORE,
                "rechecks": self.rows,
            }
        elif path == HISTORY and request.method == "POST":
            body = request.post_data_json
            assert body.keys() == {"external"}
            self.operations.append(("POST", HISTORY, body))
            value = self.row(body["external"], verified=self.next == "verified")
            self.rows = [value, *self.rows]
            if self.next == "wrong_report":
                value = value | {"report_id": OTHER}
            if self.next == "wrong_verdict":
                value = value | {"status": "accepted"}
            if self.drop:
                return route.abort()
        elif path.startswith(HISTORY + "/") and path.endswith("/handoff"):
            assert request.method == "GET" and request.post_data is None
            row_id = path.split("/")[-2]
            assert any(row["id"] == row_id for row in self.rows)
            self.operations.append(("GET", path, None))
            return route.fulfill(content_type="text/markdown", body="# Synthetic snapshot\n")
        else:
            return super().route(route)
        if path == HISTORY and self.hold == request.method:
            self.pending = (route, value)
            return None
        return route.fulfill(json=value)

    def release(self):
        route, value = self.pending
        self.pending = None
        return route.fulfill(json=value)


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
        page.locator("#tab-verification").click()
        return page, page.get_by_role("region", name="SSH 失联复验")

    yield open_page
    for page in pages:
        page.close()


def test_ssh_rechecks_append_and_download_the_original_selected_snapshot(open_report):
    contract = Contract()
    page, section = open_report(contract)
    selector = section.get_by_label("机外观察（人工记录）")
    run = section.get_by_role("button", name="运行只读失联复验")
    expect(selector).to_have_value("unavailable")
    expect(section).to_contain_text("失联前最近可比证据")
    assert [item[0] for item in contract.operations] == ["GET"]
    run.click()
    expect(section.get_by_label("复验快照")).to_have_value(contract.rows[0]["id"])
    expect(section).to_contain_text("待验收")
    expect(section).to_contain_text("未取得认证只读响应")
    first_id = contract.rows[0]["id"]

    selector.select_option("unreachable")
    run.click()
    expect(section.locator(".check-row")).to_contain_text("复验未通过")
    contract.next = "verified"
    selector.select_option("matched")
    run.click()
    expect(section.locator(".check-row")).to_contain_text("复验通过")
    expect(section).to_contain_text("机外观察（人工记录）：机外观察符合预期")
    expect(selector).to_have_value("unavailable")

    picker = section.get_by_label("复验快照")
    expect(picker.locator("option")).to_have_count(3)
    picker.select_option(first_id)
    section.get_by_role("button", name="刷新复验历史").click()
    expect(picker).to_be_enabled()
    expect(picker).to_have_value(first_id)
    assert not any(path.endswith("/handoff") for _, path, _ in contract.operations)
    with page.expect_download() as download:
        section.get_by_role("button", name="下载所选复验摘要").click()
    assert download.value.suggested_filename == "opsark-access-recheck.md"
    assert contract.operations[-1] == ("GET", f"{HISTORY}/{first_id}/handoff", None)
    assert [body for method, _, body in contract.operations if method == "POST"] == [
        {"external": "unavailable"},
        {"external": "unreachable"},
        {"external": "matched"},
    ]
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("enabled,eligible", [(False, True), (True, False)])
def test_access_rechecks_hidden_outside_the_exact_eligible_report(open_report, enabled, eligible):
    contract = Contract(enabled=enabled, eligible=eligible)
    page, section = open_report(contract)
    expect(section).to_have_count(0)
    expect(page.locator("#report-panel")).to_contain_text("恢复")
    assert contract.operations == []
    assert not contract.errors and not any(contract.counts.values())


def test_historical_rechecks_visible_without_current_registration(open_report):
    contract = Contract(can_run=False)
    contract.rows = [contract.row("matched", verified=True)]
    _, section = open_report(contract)
    expect(section).to_contain_text("仍可查看已有记录")
    expect(section.get_by_label("复验快照")).to_have_value(contract.rows[0]["id"])
    expect(section.get_by_role("button", name="运行只读失联复验")).to_have_count(0)
    expect(section.get_by_role("button", name="下载所选复验摘要")).to_be_enabled()
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("fault", ["drop", "wrong_report", "wrong_verdict"])
def test_uncertain_recheck_needs_explicit_history_readback(open_report, fault):
    contract = Contract()
    contract.drop = fault == "drop"
    contract.next = fault
    _, section = open_report(contract)
    run = section.get_by_role("button", name="运行只读失联复验")
    run.click()
    expect(section.get_by_role("alert")).to_contain_text("请先刷新历史")
    expect(run).to_have_count(0)
    expect(section.get_by_label("复验快照")).to_have_count(0)
    expect(section).not_to_contain_text(PRIVATE)
    section.get_by_role("button", name="刷新复验历史").click()
    expect(section.get_by_label("复验快照")).to_have_value(contract.rows[0]["id"])
    assert [method for method, _, _ in contract.operations] == ["GET", "POST", "GET"]
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("method,leave", [("GET", "report"), ("POST", "logout")])
def test_delayed_recheck_cannot_cross_report_or_session(open_report, method, leave):
    contract = Contract()
    contract.hold = method
    page, section = open_report(contract)
    if method == "POST":
        section.get_by_role("button", name="运行只读失联复验").click()
    expect(section.get_by_role("status")).to_contain_text("正在")
    page.wait_for_load_state("domcontentloaded")
    assert contract.pending is not None
    if leave == "report":
        page.locator(f'#report-list [data-report-id="{OTHER}"]').click()
        expect(page.locator("#report-id")).to_have_text(OTHER)
        page.locator("#tab-verification").click()
    else:
        page.locator("#logout-button").click()
        expect(page.locator("#app-shell")).to_be_hidden()
    contract.release()
    expect(section).to_have_count(0)
    assert not any(path.endswith("/handoff") for _, path, _ in contract.operations)
    assert not contract.errors and not any(contract.counts.values())
