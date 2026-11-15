"""Browser proof of report-bound maintenance claims and independent observations."""

from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import PRIVATE, TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright

REPORT = "preserved-change-report"
OTHER = "other-change-report"
PATH = f"/api/reports/{REPORT}/change-records"
AT = "2026-11-14T10:00:00Z"
BEFORE = "2026-11-14T09:00:00Z"


class Contract(ComposeContract):
    def __init__(self, *, can_record=True, source="ssh", enabled=True):
        super().__init__()
        self.base = "http://127.0.0.1:18559"
        self.rows = []
        self.requests = {}
        self.operations = []
        self.can_record = can_record
        self.source = source
        self.enabled = enabled
        self.drop = False
        self.hold = None
        self.pending = None
        self.observation = {
            "current_at": AT,
            "baseline_status": "no_baseline",
            "changes": [],
        }

    def report(self, report_id):
        return {
            "id": report_id,
            "host_id": "fixture",
            "host_name": "Synthetic host",
            "source": self.source if report_id == REPORT else "replay",
            "scenario": "container_restart",
            "scope_hash": "8" * 64,
            "created_at": AT,
            "title": "Original change report",
            "status": "inconclusive",
            "summary": "Original diagnostic outcome",
            "duration_ms": 1,
            "facts": [],
            "candidates": [],
            "missing": [],
            "evidence": [],
            "next_steps": [],
            "verification": [],
        }

    def save(self, body):
        key = body["request_id"]
        if key in self.requests:
            previous, row = self.requests[key]
            assert previous == body
            return row
        assert len(key) == 32 and all(char in "0123456789abcdef" for char in key)
        row = {
            "id": f"cr-{len(self.rows) + 1:032x}",
            "report_id": REPORT,
            "kind": body["kind"],
            "claimed_at": body["claimed_at"],
            "recorded_at": "2026-11-14T10:01:00.123456Z",
            "source": "operator_statement",
        }
        self.rows = [row, *self.rows]
        self.requests[key] = (body, row)
        return row

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/api/") or path == "/api/status":
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == "/api/capabilities":
            value = {"mode": "read_only", "change_records": self.enabled}
        elif path == "/api/reports":
            value = [self.report(REPORT), self.report(OTHER)]
        elif path in {f"/api/reports/{REPORT}", f"/api/reports/{OTHER}"}:
            value = self.report(path.rsplit("/", 1)[-1])
        elif path == PATH and request.method == "GET":
            self.operations.append(("GET", PATH, None))
            value = {
                "report_id": REPORT,
                "can_record": self.can_record,
                "records": self.rows,
                "observation": self.observation,
            }
        elif path == PATH and request.method == "POST":
            body = request.post_data_json
            assert body.keys() == {"request_id", "kind", "claimed_at"}
            self.operations.append(("POST", PATH, body))
            value = self.save(body)
            if self.drop:
                return route.abort()
        elif path.startswith(PATH + "/") and path.endswith("/handoff"):
            assert request.method == "GET" and request.post_data is None
            record_id = path.split("/")[-2]
            assert any(record["id"] == record_id for record in self.rows)
            self.operations.append(("GET", path, None))
            return route.fulfill(content_type="text/markdown", body="# Synthetic selected record\n")
        else:
            return super().route(route)
        if path == PATH and self.hold == request.method:
            self.pending = (route, value)
            return None
        return route.fulfill(json=value)

    def release(self):
        route, value = self.pending
        self.pending = None
        route.fulfill(json=value)


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
        return page, page.get_by_role("region", name="近期变更记录")

    yield open_page
    for page in pages:
        page.close()


def test_old_statement_is_selectable_and_has_independent_date_and_export(open_report):
    contract = Contract()
    page, section = open_report(contract)
    expect(section).to_contain_text("没有可比基线")
    expect(section).to_contain_text("此前变更无法从本报告追溯")
    assert contract.operations and all(item[0] == "GET" for item in contract.operations)
    section.get_by_label("变更类型").select_option("application_configuration")
    section.get_by_label("声明时间精度").select_option("date")
    section.get_by_label("声明日期").fill("2026-11-13")
    section.get_by_role("button", name="保存维护者陈述").click()
    expect(section).to_contain_text("声明时间：2026-11-13（仅日期）")
    expect(section).to_contain_text("实际变更时刻、部署来源和操作者均未知")
    expect(page.locator("#report-status")).to_have_text("证据不足")
    expect(section.get_by_label("声明时间精度")).to_have_value("unknown")
    first_id = contract.rows[0]["id"]
    section.get_by_role("button", name="保存维护者陈述").click()
    expect(section).to_contain_text("声明时间：时间未知")
    picker = section.get_by_label("所选陈述")
    picker.select_option(first_id)
    section.get_by_role("button", name="刷新变更记录").click()
    expect(picker).to_be_enabled()
    expect(picker).to_have_value(first_id)
    assert not any(path.endswith("/handoff") for _, path, _ in contract.operations)
    with page.expect_download() as download:
        section.get_by_role("button", name="下载所选变更记录").click()
    assert download.value.suggested_filename == "opsark-change-record.md"
    assert contract.operations[-1] == ("GET", f"{PATH}/{first_id}/handoff", None)
    assert not contract.errors and not any(contract.counts.values())


def test_lost_response_reuses_exact_payload_after_report_navigation(open_report):
    contract = Contract()
    contract.drop = True
    page, section = open_report(contract)
    section.get_by_label("变更类型").select_option("compose_configuration")
    section.get_by_label("声明时间精度").select_option("instant")
    section.get_by_label("声明时刻（UTC）").fill("2026-11-12T23:44:07")
    section.get_by_role("button", name="保存维护者陈述").click()
    expect(section.get_by_role("alert")).to_contain_text("确认")
    assert not any(method == "POST" for method, _, _ in contract.operations)
    section.get_by_label("我确认填写的是 UTC 时刻").check()
    section.get_by_role("button", name="保存维护者陈述").click()
    expect(section.get_by_role("alert")).to_contain_text("原请求编号")
    expect(section.get_by_label("变更类型")).to_have_count(0)
    page.locator(f'#report-list [data-report-id="{OTHER}"]').click()
    expect(page.locator("#report-id")).to_have_text(OTHER)
    expect(section).to_have_count(0)
    page.locator(f'#report-list [data-report-id="{REPORT}"]').click()
    expect(page.locator("#report-id")).to_have_text(REPORT)
    expect(section).to_contain_text("2026-11-12T23:44:07Z（UTC）")
    contract.drop = False
    section.get_by_role("button", name="重试原陈述").click()
    expect(section.get_by_role("button", name="保存维护者陈述")).to_be_enabled()
    posts = [body for method, _, body in contract.operations if method == "POST"]
    assert len(posts) == 2 and posts[0] == posts[1]
    assert posts[0]["claimed_at"] == {"precision": "instant", "value": "2026-11-12T23:44:07Z"}
    assert len(contract.rows) == 1
    assert not contract.errors and not any(contract.counts.values())


def test_read_only_history_and_two_point_changes_render_separately(open_report):
    contract = Contract(can_record=False)
    contract.observation = {
        "current_at": AT,
        "baseline_status": "incomplete",
        "changes": [{"field": "image", "from_at": BEFORE, "to_at": AT}],
    }
    contract.save(
        {
            "request_id": "1" * 32,
            "kind": "image_update",
            "claimed_at": {"precision": "date", "value": "2020-01-01"},
        }
    )
    _, section = open_report(contract)
    expect(section).to_contain_text("当前条件不支持新增陈述")
    expect(section).to_contain_text("部分字段缺少可比证据")
    expect(section.locator("ul li")).to_have_count(1)
    expect(section.locator("ul li")).to_contain_text(
        "镜像发生变化：(2026-11-14T09:00:00Z（UTC），2026-11-14T10:00:00Z（UTC）]"
    )
    expect(section.locator("ul li")).not_to_contain_text("2020-01-01")
    expect(section).to_contain_text("声明时间：2020-01-01（仅日期）")
    expect(section.get_by_role("button", name="下载所选变更记录")).to_be_enabled()
    expect(section.get_by_role("button", name="保存维护者陈述")).to_have_count(0)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("enabled,source", [(False, "ssh"), (True, "replay")])
def test_hidden_outside_authenticated_ssh_report_capability(open_report, enabled, source):
    contract = Contract(enabled=enabled, source=source)
    _, section = open_report(contract)
    expect(section).to_have_count(0)
    assert contract.operations == []
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("variant", ["extra", "wrong_current_time", "two_baselines"])
def test_untrusted_history_does_not_render_or_offer_write(open_report, variant):
    contract = Contract()
    if variant == "extra":
        contract.observation["extra"] = PRIVATE
    else:
        contract.observation.update(
            baseline_status="compared",
            changes=[
                {"field": "image", "from_at": BEFORE, "to_at": AT},
                {
                    "field": "container",
                    "from_at": "2026-11-14T09:00:00.000001Z"
                    if variant == "two_baselines"
                    else BEFORE,
                    "to_at": "2026-11-14T10:00:00.000001Z"
                    if variant == "wrong_current_time"
                    else AT,
                },
            ],
        )
    page, section = open_report(contract)
    expect(section.get_by_role("alert")).to_contain_text("无法核实变更记录")
    expect(section.get_by_role("button", name="保存维护者陈述")).to_have_count(0)
    expect(page.locator("#report-panel")).not_to_contain_text(PRIVATE)
    assert not contract.errors and not any(contract.counts.values())


def test_precise_observation_interval_accepts_two_points_within_same_millisecond(open_report):
    contract = Contract()
    contract.observation = {
        "current_at": "2026-11-14T10:00:00.000002Z",
        "baseline_status": "compared",
        "changes": [
            {
                "field": "image",
                "from_at": "2026-11-14T10:00:00.000001Z",
                "to_at": "2026-11-14T10:00:00.000002Z",
            }
        ],
    }
    _, section = open_report(contract)
    expect(section.locator("ul li")).to_contain_text(
        "镜像发生变化：(2026-11-14T10:00:00.000001Z（UTC），2026-11-14T10:00:00.000002Z（UTC）]"
    )
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_delayed_change_reply_cannot_cross_report_or_logout(open_report, method):
    contract = Contract()
    contract.hold = method
    page, section = open_report(contract)
    if method == "POST":
        section.get_by_role("button", name="保存维护者陈述").click()
    expect(section.get_by_role("status")).to_contain_text("正在")
    page.wait_for_load_state("domcontentloaded")
    assert contract.pending is not None
    if method == "GET":
        page.locator(f'#report-list [data-report-id="{OTHER}"]').click()
        expect(page.locator("#report-id")).to_have_text(OTHER)
    else:
        page.locator("#logout-button").click()
        expect(page.locator("#app-shell")).to_be_hidden()
    contract.release()
    expect(section).to_have_count(0)
    assert not contract.errors and not any(contract.counts.values())
