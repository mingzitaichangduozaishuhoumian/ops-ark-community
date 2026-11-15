"""Test the report-bound container business recheck in a local browser."""

from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import PRIVATE, TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright

REPORT = "container-report-a"
OTHER = "container-report-b"
PATH = f"/api/reports/{REPORT}/container-rechecks"
AT = "2026-11-14T10:01:00.123456Z"


class Contract(ComposeContract):
    def __init__(self, *, can_run=True, source="ssh", scenario="container_restart", enabled=True):
        super().__init__()
        self.base = "http://127.0.0.1:18562"
        self.rows = []
        self.requests = {}
        self.operations = []
        self.can_run = can_run
        self.source = source
        self.scenario = scenario
        self.enabled = enabled
        self.drop = False
        self.hold = False
        self.pending = None
        self.outcomes = ["passed", "inconclusive", "uncovered"]
        self.management = "verified"

    def report(self, report_id):
        return {
            "id": report_id,
            "host_id": "fixture",
            "host_name": "Synthetic host",
            "scope_hash": "8" * 64,
            "scenario": self.scenario if report_id == REPORT else "disk",
            "source": self.source,
            "created_at": AT,
            "title": "Container investigation",
            "status": "inconclusive",
            "summary": "Synthetic diagnostic",
            "duration_ms": 1,
            "facts": [],
            "candidates": [],
            "missing": [],
            "evidence": [],
            "verification": [],
            "next_steps": [],
        }

    def save(self, request_id):
        if request_id in self.requests:
            return self.requests[request_id]
        assert len(request_id) == 32 and all(char in "0123456789abcdef" for char in request_id)
        status = "pending"
        if "failed" in self.outcomes:
            status = "failed"
        elif self.management == "verified" and all(check == "passed" for check in self.outcomes):
            status = "passed"
        row = {
            "id": f"rr-{len(self.rows) + 1:032x}",
            "report_id": REPORT,
            "finished_at": AT,
            "management": self.management,
            "checks": list(self.outcomes),
            "status": status,
        }
        self.rows = [row, *self.rows]
        self.requests[request_id] = row
        return row

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/api/") or path == "/api/status":
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == "/api/capabilities":
            value = {"mode": "read_only", "container_report_rechecks": self.enabled}
        elif path == "/api/reports":
            value = [self.report(REPORT), self.report(OTHER)]
        elif path in {f"/api/reports/{REPORT}", f"/api/reports/{OTHER}"}:
            value = self.report(path.rsplit("/", 1)[-1])
        elif path == PATH and request.method == "GET":
            self.operations.append(("GET", PATH, None))
            value = {"report_id": REPORT, "can_run": self.can_run, "rechecks": self.rows}
        elif path == PATH and request.method == "POST":
            body = request.post_data_json
            assert body.keys() == {"request_id"}
            self.operations.append(("POST", PATH, body))
            value = self.save(body["request_id"])
            if self.drop:
                return route.abort()
            if self.hold:
                self.pending = (route, value)
                return None
        elif path.startswith(PATH + "/") and path.endswith("/handoff"):
            assert request.method == "GET" and request.post_data is None
            record_id = path.split("/")[-2]
            assert any(record["id"] == record_id for record in self.rows)
            self.operations.append(("GET", path, None))
            return route.fulfill(content_type="text/markdown", body="# Synthetic recheck\n")
        else:
            return super().route(route)
        return route.fulfill(json=value)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright, launch_fixture_browser(playwright) as instance:
        yield instance


def select_report(page, report_id):
    page.locator(f'#report-list [data-report-id="{report_id}"]').click()
    expect(page.locator("#report-id")).to_have_text(report_id)
    page.locator("#tab-verification").click()


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
        select_report(page, REPORT)
        return page, page.get_by_role("region", name="容器调查业务复验")

    yield open_page
    for page in pages:
        page.close()


def test_container_rechecks_fail_pending_pass_and_download_selected_history(open_report):
    contract = Contract()
    page, section = open_report(contract)
    run = section.get_by_role("button", name="运行容器调查只读复验")
    expect(run).to_be_enabled()
    assert all(method == "GET" for method, _, _ in contract.operations)
    contract.outcomes = ["failed", "passed", "inconclusive"]
    run.click()
    expect(section.locator(".check-row")).to_contain_text("复验未通过")
    first_id = contract.rows[0]["id"]

    contract.outcomes = ["passed", "inconclusive", "uncovered"]
    run.click()
    expect(section.locator(".check-row")).to_contain_text("待验收")
    expect(section.locator("ol li")).to_have_text(["通过", "证据不足", "未覆盖"])
    contract.outcomes = ["passed", "passed", "passed"]
    run.click()
    expect(section.locator(".check-row")).to_contain_text("复验通过")
    expect(page.locator("#report-status")).to_have_text("证据不足")

    picker = section.get_by_label("容器复验快照")
    expect(picker.locator("option")).to_have_count(3)
    picker.select_option(first_id)
    section.get_by_role("button", name="刷新容器复验历史").click()
    expect(picker).to_be_enabled()
    expect(picker).to_have_value(first_id)
    assert not any(path.endswith("/handoff") for _, path, _ in contract.operations)
    with page.expect_download() as download:
        section.get_by_role("button", name="下载所选容器复验摘要").click()
    assert download.value.suggested_filename == "opsark-container-recheck.md"
    assert contract.operations[-1] == ("GET", f"{PATH}/{first_id}/handoff", None)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("allows_new", [True, False])
def test_dropped_receipt_retries_same_request_and_makes_no_extra_record(open_report, allows_new):
    contract = Contract()
    contract.drop = True
    page, section = open_report(contract)
    section.get_by_role("button", name="运行容器调查只读复验").click()
    expect(section.get_by_role("alert")).to_contain_text("原请求编号")
    select_report(page, OTHER)
    expect(section).to_have_count(0)
    contract.can_run = allows_new
    select_report(page, REPORT)
    expect(section.get_by_label("容器复验快照")).to_have_value(contract.rows[0]["id"])
    contract.drop = False
    retry = section.get_by_role("button", name="重试原容器复验")
    retry.click()
    expect(retry).to_have_count(0)
    run = section.get_by_role("button", name="运行容器调查只读复验")
    if allows_new:
        expect(run).to_be_enabled()
    else:
        expect(run).to_have_count(0)
    posts = [body for method, _, body in contract.operations if method == "POST"]
    assert len(posts) == 2 and posts[0] == posts[1] and len(contract.rows) == 1
    assert not contract.errors and not any(contract.counts.values())


def test_old_rechecks_remain_selectable_without_current_registration(open_report):
    contract = Contract(can_run=False)
    row = contract.save("a" * 32)
    _, section = open_report(contract)
    expect(section).to_contain_text("仍可查看已有记录")
    expect(section.get_by_label("容器复验快照")).to_have_value(row["id"])
    expect(section.get_by_role("button", name="下载所选容器复验摘要")).to_be_enabled()
    expect(section.get_by_role("button", name="运行容器调查只读复验")).to_have_count(0)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("invalid", ["outcome", "scope", "raw"])
def test_untrusted_rechecks_are_not_rendered(open_report, invalid):
    contract = Contract()
    row = contract.save("a" * 32)
    if invalid == "outcome":
        row["status"] = "passed"
    elif invalid == "scope":
        row["report_id"] = OTHER
    else:
        row["raw"] = PRIVATE
    _, section = open_report(contract)
    expect(section.get_by_role("alert")).to_contain_text("未能核实复验历史")
    expect(section).not_to_contain_text(PRIVATE)
    expect(section.locator("ol li")).to_have_count(0)
    expect(section.get_by_role("button", name="运行容器调查只读复验")).to_have_count(0)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize(
    "enabled,source,scenario",
    [
        (False, "ssh", "container_restart"),
        (True, "replay", "container_restart"),
        (True, "ssh", "disk"),
    ],
)
def test_unavailable_outside_eligible_original_report(open_report, enabled, source, scenario):
    contract = Contract(enabled=enabled, source=source, scenario=scenario)
    _, section = open_report(contract)
    expect(section).to_have_count(0)
    assert contract.operations == []
    assert not contract.errors and not any(contract.counts.values())


def test_recheck_reply_after_logout_never_displays_or_downloads(open_report):
    contract = Contract()
    contract.hold = True
    page, section = open_report(contract)
    section.get_by_role("button", name="运行容器调查只读复验").click()
    expect(section.get_by_role("status")).to_contain_text("正在运行")
    page.wait_for_load_state("domcontentloaded")
    assert contract.pending is not None
    page.locator("#logout-button").click()
    expect(page.locator("#app-shell")).to_be_hidden()
    route, value = contract.pending
    route.fulfill(json=value)
    expect(section).to_have_count(0)
    assert not any(path.endswith("/handoff") for _, path, _ in contract.operations)
    assert not contract.errors and not any(contract.counts.values())
