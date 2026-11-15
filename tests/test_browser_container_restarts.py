"""Browser contract for restart previews, explicit impact reads and lost replies."""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import (
    PRIVATE,
    ROOT,
    TOKEN,
    ComposeContract,
    launch_fixture_browser,
)
from playwright.sync_api import expect, sync_playwright

BASE = "/api/container-restarts"
PLAN = "a" * 32
SITE = "public.example.test"
IMPACT = f"{BASE}/{PLAN}/impact"
DEPENDENCIES = "9" * 64


class Contract(ComposeContract):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.base = "http://127.0.0.1:18542"
        self.operations = []
        self.row = None
        self.hold_impact = False
        self.pending_impact = None
        self.host_reads = 0
        self.dependency_binding = DEPENDENCIES
        self.impact = {
            "plan_id": PLAN,
            "binding_digest": DEPENDENCIES,
            "status": "observed",
            "reason": None,
            "observed_at": "2026-11-14T10:30:00.123456Z",
            "loaded_generation": "unknown",
            "sites": [{"domain": SITE, "file": "/etc/nginx/conf.d/public.conf", "line": 42}],
        }

    @staticmethod
    def reply(route, value):
        route.fulfill(content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        if not request.url.startswith(self.base + "/"):
            return super().route(route)
        path = urlsplit(request.url).path
        if path == "/container-restarts.js":
            return route.fulfill(
                content_type="text/javascript",
                body=(ROOT / "web" / "container-restarts.js").read_bytes(),
            )
        if path == "/api/capabilities":
            return self.reply(
                route, {"mode": "read_only", "container_restart": True, "automation_modes": True}
            )
        if path == "/api/automation":
            return self.reply(
                route, {"mode": self.mode, "revision": 17, "mode_sync_complete": True}
            )
        if path == "/api/hosts":
            assert request.method == "GET"
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            self.host_reads += 1
            return self.reply(
                route,
                [
                    {
                        "id": "web-a",
                        "name": "Web A",
                        "source": "ssh",
                        "address": "192.0.2.2",
                        "port": 22,
                        "container_restart_configured": True,
                        "container_restart_binding_digest": "b" * 64,
                        "nginx_dependencies_configured": True,
                        "nginx_dependency_binding_digest": self.dependency_binding,
                    },
                    {
                        "id": "web-b",
                        "name": "Web B",
                        "source": "ssh",
                        "address": "192.0.2.3",
                        "port": 22,
                        "container_restart_configured": True,
                        "container_restart_binding_digest": "c" * 64,
                        "nginx_dependencies_configured": True,
                        "nginx_dependency_binding_digest": "8" * 64,
                    },
                ],
            )
        if not path.startswith(BASE):
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        body = request.post_data_json if request.post_data else None
        self.operations.append((request.method, path, body))
        if path == BASE:
            return self.reply(route, [self.row] if self.row else [])
        if path == BASE + "/prepare":
            assert body == {"host_id": "web-a", "expected_mode_revision": 17}
            now = datetime.now(UTC)
            self.row = {
                "plan_id": PLAN,
                "host_id": "web-a",
                "binding_digest": "b" * 64,
                "status": "ready",
                "created_at": now.isoformat(),
                "approved": False,
                "blocking": False,
                "prepare_reason": None,
                "receipt": None,
                "plan": {
                    "schema_version": 1,
                    "status": "ready",
                    "policy_digest": "e" * 64,
                    "plan_id": PLAN,
                    "action_id": "f" * 64,
                    "mode_revision": 17,
                    "plan_digest": "d" * 64,
                    "container_id": "1" * 64,
                    "image_id": "sha256:" + "2" * 64,
                    "expires_at": (now + timedelta(minutes=5)).isoformat(),
                    "impact": {
                        "expected_downtime_seconds": None,
                        "no_recreate": True,
                        "no_volume_changes": True,
                    },
                },
            }
            return self.reply(route, self.row)
        if path == IMPACT:
            assert request.method == "POST" and body == {}
            if self.hold_impact:
                self.pending_impact = route
                return None
            return self.reply(route, self.impact)
        if path == BASE + "/" + PLAN + "/approve":
            assert body == {
                "expected_plan_digest": "d" * 64,
                "expected_mode_revision": 17,
                "confirm": True,
            }
            self.row.update(status="unknown", approved=True, blocking=True)
            return route.abort()
        if path == BASE + "/" + PLAN:
            return self.reply(route, self.row)
        if path == BASE + "/" + PLAN + "/observe":
            assert body is None
            receipt = {
                key: self.row["plan"][key]
                for key in ("policy_digest", "action_id", "plan_id", "plan_digest", "mode_revision")
            }
            receipt.update(
                schema_version=1, status="unknown", reason=None, reconciliation_status="verified"
            )
            self.row.update(blocking=False, receipt=receipt)
            return self.reply(route, self.row)
        raise AssertionError("Unexpected restart route")


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright, launch_fixture_browser(playwright) as instance:
        yield instance


@pytest.fixture
def restart_panel(browser):
    pages = []

    def open_panel(contract, width=1440):
        page = browser.new_page(viewport={"width": width, "height": 930}, service_workers="block")
        pages.append(page)
        page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
        page.route("**/*", contract.route)
        page.goto(contract.base)
        page.wait_for_load_state("networkidle")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        page.locator("#remediation-nav").click()
        panel = page.locator("#container-restarts-section")
        panel.get_by_role("button", name="生成重启预览").click()
        expect(panel.get_by_role("article")).to_contain_text("1" * 64)
        return page, panel

    yield open_panel
    for page in pages:
        page.close()


@pytest.mark.parametrize(
    ("mode", "width"), [("assisted", 320), ("assisted", 1440), ("manual", 1440)]
)
def test_single_approval_and_same_original_read_only_recovery(mode, width, restart_panel):
    contract = Contract(mode)
    _, panel = restart_panel(contract, width)
    if mode == "manual":
        expect(panel.get_by_role("button", name="复核并批准")).to_have_count(0)
    else:
        panel.get_by_role("button", name="复核并批准").click()
        dialog = panel.get_by_role("dialog")
        expect(dialog.get_by_role("button", name="批准一次重启")).to_be_disabled()
        dialog.get_by_role("checkbox").check()
        dialog.get_by_role("button", name="批准一次重启").click()
        expect(panel.get_by_role("alert")).to_contain_text("批准结果待核实")
        expect(panel.get_by_role("button", name="复核并批准")).to_have_count(0)
        panel.get_by_role("button", name="查询原任务", exact=True).click()
        panel.get_by_role("button", name="只读复验原任务").click()
        expect(panel.get_by_role("article")).to_contain_text("原回执未知 · 容器重启已复验")
        assert [route for method, route, _ in contract.operations if method == "POST"] == [
            BASE + "/prepare",
            BASE + "/" + PLAN + "/approve",
            BASE + "/" + PLAN + "/observe",
        ]
    assert not any(path == IMPACT for _, path, _ in contract.operations)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("mode", ["manual", "assisted"])
def test_explicit_impact_only_displays_disk_sites(mode, restart_panel):
    contract = Contract(mode)
    _, panel = restart_panel(contract)
    assert not any(path == IMPACT for _, path, _ in contract.operations)
    host_reads = contract.host_reads
    panel.get_by_role("button", name="检查站点影响（只读）").click()
    details = panel.get_by_role("article").get_by_role("status")
    expect(details).to_contain_text(f"{SITE} · /etc/nginx/conf.d/public.conf:42")
    expect(details).to_contain_text("当前生效的 Nginx 配置尚未核实")
    expect(details.locator("time")).to_have_attribute("datetime", contract.impact["observed_at"])
    assert contract.host_reads == host_reads + 1
    assert [item for item in contract.operations if item[0] == "POST"] == [
        ("POST", BASE + "/prepare", {"host_id": "web-a", "expected_mode_revision": 17}),
        ("POST", IMPACT, {}),
    ]
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize(
    ("update", "message"),
    [
        (
            {
                "status": "unavailable",
                "reason": "ambiguous_binding",
                "observed_at": None,
                "sites": [],
            },
            "站点与容器的关联存在歧义",
        ),
        ({"sites": []}, "本次未发现可核实的磁盘站点关联"),
        ({"plan_id": "c" * 32}, "未取得可核实的站点影响检查结果"),
        ({"binding_digest": "7" * 64}, "未取得可核实的站点影响检查结果"),
        ({"raw_log": PRIVATE}, "未取得可核实的站点影响检查结果"),
        (
            {"sites": [{"domain": SITE, "file": "/etc/nginx/../" + PRIVATE, "line": 42}]},
            "未取得可核实的站点影响检查结果",
        ),
    ],
)
def test_unavailable_and_untrusted_impact_cannot_supply_sites(update, message, restart_panel):
    contract = Contract("assisted")
    contract.impact.update(update)
    _, panel = restart_panel(contract)
    panel.get_by_role("button", name="检查站点影响（只读）").click()
    details = panel.get_by_role("article").get_by_role("status")
    expect(details).to_contain_text(message)
    expect(details).not_to_contain_text(SITE)
    expect(panel).not_to_contain_text(PRIVATE)
    expect(panel.get_by_role("button", name="复核并批准")).to_be_enabled()
    assert not any(path.endswith("/approve") for _, path, _ in contract.operations)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("live_binding", ["7" * 64, None])
def test_impact_rechecks_live_dependency_binding_before_display(live_binding, restart_panel):
    contract = Contract("assisted")
    contract.hold_impact = True
    _, panel = restart_panel(contract)
    host_reads = contract.host_reads
    inspect = panel.get_by_role("button", name="检查站点影响（只读）")
    inspect.click()
    details = panel.get_by_role("article").get_by_role("status")
    expect(details).to_contain_text("正在检查")
    assert contract.pending_impact is not None
    # The host, restart registration and response all retain their original values.
    # Only the live Nginx/Compose registration changes while the response is pending.
    contract.dependency_binding = live_binding
    contract.reply(contract.pending_impact, contract.impact)
    expect(details).to_contain_text("Nginx 或 Compose 登记范围已变化或无法核实")
    expect(details).not_to_contain_text(SITE)
    expect(panel.get_by_role("button", name="复核并批准")).to_be_enabled()
    assert contract.host_reads == host_reads + 1
    assert [item for item in contract.operations if item[1] == IMPACT] == [("POST", IMPACT, {})]
    assert not any(path.endswith("/approve") for _, path, _ in contract.operations)
    assert not contract.errors and not any(contract.counts.values())


@pytest.mark.parametrize("invalidate", ["host", "view", "logout", "expiry", "approval"])
def test_late_impact_cannot_restore_invalidated_context(invalidate, restart_panel):
    contract = Contract("assisted")
    contract.hold_impact = True
    page, panel = restart_panel(contract)
    if invalidate == "expiry":
        expires = datetime.fromisoformat(contract.row["plan"]["expires_at"])
        page.clock.install()
        page.clock.pause_at(expires - timedelta(seconds=10))
    inspect = panel.get_by_role("button", name="检查站点影响（只读）")
    inspect.click()
    expect(inspect).to_be_disabled()
    expect(panel.get_by_role("article").get_by_role("status")).to_contain_text("正在检查")
    assert contract.pending_impact is not None
    if invalidate == "logout":
        page.locator("#logout-button").click()
        expect(page.locator("#app-shell")).to_be_hidden()
    elif invalidate == "view":
        page.locator('[data-view="workspace"]').click()
        expect(panel).to_be_hidden()
    elif invalidate == "host":
        panel.get_by_label("登记目标").select_option("web-b")
        expect(inspect).to_have_count(0)
    elif invalidate == "expiry":
        page.clock.fast_forward(10_001)
        expect(inspect).to_have_count(0)
    else:
        panel.get_by_role("button", name="复核并批准").click()
        dialog = panel.get_by_role("dialog")
        dialog.get_by_role("checkbox").check()
        dialog.get_by_role("button", name="批准一次重启").click()
        expect(panel.get_by_role("alert")).to_contain_text("批准结果待核实")
        expect(inspect).to_have_count(0)
    contract.reply(contract.pending_impact, contract.impact)
    page.wait_for_load_state("networkidle")
    if invalidate == "host":
        panel.get_by_label("登记目标").select_option("web-a")
    elif invalidate == "view":
        page.locator("#remediation-nav").click()
    elif invalidate == "logout":
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        page.locator("#remediation-nav").click()
    expect(panel.get_by_role("article")).not_to_contain_text(SITE)
    assert [item for item in contract.operations if item[1] == IMPACT] == [("POST", IMPACT, {})]
    assert not contract.errors and not any(contract.counts.values())
