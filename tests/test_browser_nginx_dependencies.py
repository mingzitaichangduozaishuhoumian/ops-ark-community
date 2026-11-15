"""Real headless browsers with every resource and API fulfilled from synthetic data."""

import copy
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import PRIVATE, TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright
from test_nginx_dependencies import joined, projection, server

ROOT = Path(__file__).resolve().parents[1]


class Contract(ComposeContract):
    def __init__(
        self, tmp_path, *, configured=True, hold=False, mutation=None, path=False, hold_path=False
    ):
        super().__init__(configured=configured, hold=hold)
        self.base = "http://127.0.0.1:18488"
        self.value = joined(tmp_path, projection(server() + server("b.example.test"))).model_dump(
            mode="json"
        )
        self.mutation = mutation
        self.observations = 0
        self.scope_digest = self.value["scope_digest"]
        self.binding_digest = self.value["binding_digest"]
        self.path_binding = "d" * 64 if path else None
        self.hold_path = hold_path
        self.pending_path = None
        self.path_observations = 0
        self.host_reads = 0
        self.path_value = {
            "host_id": "fixture",
            "binding_digest": self.path_binding,
            "observed_at": "2026-11-14T10:30:00.123456Z",
            "status": "passed",
            "checks": [
                {
                    "id": "readiness",
                    "status": "passed",
                    "http_status": 200,
                    "status_matches": True,
                    "body_matches": True,
                }
            ],
        }

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base + "/"):
            return super().route(route)
        if path == "/nginx-dependencies.js":
            route.fulfill(
                content_type="text/javascript",
                body=(ROOT / "web/nginx-dependencies.js").read_bytes(),
            )
        elif path == "/api/capabilities":
            route.fulfill(
                content_type="application/json",
                body=json.dumps(
                    {
                        "mode": "read_only",
                        "host_nginx_dependencies": True,
                        "security_observation": False,
                    }
                ),
            )
        elif path == "/api/hosts":
            self.host_reads += 1
            route.fulfill(
                content_type="application/json",
                body=json.dumps(
                    [
                        {
                            "id": "fixture",
                            "name": "Synthetic Nginx",
                            "address": "192.0.2.10",
                            "port": 22,
                            "username": "opsark-readonly",
                            "source": "ssh",
                            "health_checks": [],
                            "container_binding_confirmed": False,
                            "nginx_dependencies_configured": self.configured,
                            "nginx_dependency_scope_digest": self.scope_digest,
                            "nginx_dependency_binding_digest": self.binding_digest,
                            **(
                                {"nginx_path_observation_binding_digest": self.path_binding}
                                if self.path_binding is not None
                                else {}
                            ),
                        }
                    ]
                ),
            )
        elif path == "/api/hosts/fixture/nginx-dependencies":
            assert request.method == "POST" and request.post_data_json == {}
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            self.observations += 1
            if self.hold:
                self.pending = route
                return
            value = copy.deepcopy(self.value)
            if self.mutation:
                self.mutation(value)
            route.fulfill(content_type="application/json", body=json.dumps(value))
        elif path == "/api/hosts/fixture/nginx-path-observation":
            assert request.method == "POST" and request.post_data_json == {}
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            self.path_observations += 1
            if self.hold_path:
                self.pending_path = route
                return
            route.fulfill(content_type="application/json", body=json.dumps(self.path_value))
        else:
            super().route(route)

    def release(self):
        route, self.pending = self.pending, None
        route.fulfill(content_type="application/json", body=json.dumps(self.value))

    def release_path(self):
        route, self.pending_path = self.pending_path, None
        route.fulfill(content_type="application/json", body=json.dumps(self.path_value))


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_fixture_browser(playwright)
        yield instance
        instance.close()


@pytest.fixture
def console(browser, tmp_path):
    contexts, contracts = [], []

    def open_console(**options):
        contract = Contract(tmp_path, **options)
        contracts.append(contract)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000}, service_workers="block"
        )
        contexts.append(context)
        page = context.new_page()
        page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
        page.route("**/*", contract.route)
        page.goto(contract.base)
        page.wait_for_load_state("networkidle")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        page.locator('button[data-view="hosts"]').click()
        return page, contract

    yield open_console
    for context in contexts:
        context.close()
    assert all(
        not contract.errors
        and not any(
            contract.counts[k]
            for k in ("external_requests", "unexpected_routes", "forbidden_writes")
        )
        for contract in contracts
    )


@pytest.mark.parametrize("width", [320, 1440])
def test_automatic_relationships_shared_sites_and_disk_boundary(console, tmp_path, width):
    page, contract = console()
    page.set_viewport_size({"width": width, "height": 950})
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel).to_contain_text("a.example.test")
    expect(panel).to_contain_text("b.example.test")
    expect(panel).to_contain_text("唯一 Compose 候选")
    expect(panel).to_contain_text("共享本机上游")
    expect(panel).to_contain_text("已加载代次未知")
    assert contract.observations == 1 and panel.get_by_role("button").count() == 1
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    page.screenshot(path=str(tmp_path / f"nginx-dependencies-{width}.png"), full_page=True)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(raw_config=PRIVATE),
        lambda v: v.update(actions_enabled=True),
        lambda v: v.update(loaded_generation="confirmed"),
        lambda v: v["relationships"][0].update(raw=PRIVATE),
    ],
)
def test_invalid_reply_is_wholly_rejected_without_raw_or_partial_rows(console, mutation):
    page, _ = console(mutation=mutation)
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel).to_contain_text("未显示部分关系")
    assert (
        "a.example.test" not in panel.inner_text()
        and PRIVATE not in page.locator("body").inner_text()
    )


def test_late_reply_after_logout_is_not_attached_to_another_session(console):
    page, contract = console(hold=True)
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel.locator("[data-nginx-dependencies-run]")).to_be_disabled()
    page.locator("#logout-button").click()
    contract.release()
    expect(page.locator("#login-screen")).to_be_visible()
    assert "a.example.test" not in page.locator("body").inner_text()


def test_unregistered_scope_cannot_be_enabled_by_browser(console):
    page, contract = console(configured=False)
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    expect(panel.locator("[data-nginx-dependencies-run]")).to_be_disabled()
    assert contract.observations == 0
    assert panel.locator("[data-nginx-path-observation-run]").count() == 0
    assert contract.path_observations == 0


@pytest.mark.parametrize("change", ["scope", "project"])
def test_same_host_late_reply_is_rejected_after_registered_scope_or_project_changes(
    console, change
):
    page, contract = console(hold=True)
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel.locator("[data-nginx-dependencies-run]")).to_be_disabled()
    if change == "scope":
        contract.scope_digest = "b" * 64
    contract.binding_digest = "c" * 64
    contract.release()
    expect(panel).to_contain_text("未显示部分关系")
    assert "a.example.test" not in panel.inner_text()


@pytest.mark.parametrize("width", [320, 1440])
def test_registered_route_observation_is_explicit_and_separate_from_disk(console, width):
    page, contract = console(path=True)
    page.set_viewport_size({"width": width, "height": 950})
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    routes = panel.locator("[data-nginx-path-observation]")
    expect(routes).to_contain_text("登记路径响应")
    assert contract.path_observations == 0
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel.locator(".nginx-dependencies-result")).to_contain_text("已加载代次未知")
    assert contract.path_observations == 0
    host_reads = contract.host_reads
    routes.get_by_role("button", name="检查登记路径响应").click()
    expect(routes).to_contain_text("响应符合登记条件")
    expect(routes).to_contain_text("HTTP 200 · 状态 匹配 · 正文 匹配")
    assert contract.path_observations == 1 and contract.host_reads > host_reads
    assert contract.observations == 1
    assert "a.example.test" not in routes.inner_text()
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")


def test_timeout_stays_inconclusive_and_disk_error_preserves_observation(console):
    page, contract = console(path=True, mutation=lambda value: value.update(raw=PRIVATE))
    contract.path_value.update(status="inconclusive")
    contract.path_value["checks"][0].update(
        status="inconclusive", http_status=None, status_matches=None, body_matches=None
    )
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    routes = panel.locator("[data-nginx-path-observation]")
    routes.locator("[data-nginx-path-observation-run]").click()
    expect(routes).to_contain_text("证据不足")
    expect(routes).to_contain_text("HTTP 未取得")
    expect(routes).not_to_contain_text("响应符合登记条件")
    panel.locator("[data-nginx-dependencies-run]").click()
    expect(panel.locator(".nginx-dependencies-result")).to_contain_text("未显示部分关系")
    expect(routes).to_contain_text("证据不足")
    assert contract.path_observations == 1 and PRIVATE not in page.locator("body").inner_text()


@pytest.mark.parametrize("change", ["profile", "scope", "logout"])
def test_route_observation_drops_late_replies_after_registration_or_session_change(console, change):
    page, contract = console(path=True, hold_path=True)
    panel = page.locator('[data-nginx-dependencies="fixture"]')
    disk = panel.locator(".nginx-dependencies-result")
    if change != "logout":
        panel.locator("[data-nginx-dependencies-run]").click()
        expect(disk).to_contain_text("a.example.test")
    button = panel.locator("[data-nginx-path-observation-run]")
    button.click()
    expect(button).to_be_disabled()
    if change == "logout":
        page.locator("#logout-button").click()
        contract.release_path()
        expect(page.locator("#login-screen")).to_be_visible()
        assert "响应符合登记条件" not in page.locator("body").inner_text()
        return
    if change == "scope":
        contract.scope_digest = "e" * 64
    else:
        contract.path_binding = "e" * 64
    contract.release_path()
    expect(panel.locator("[data-nginx-path-observation]")).to_contain_text("登记范围已变更")
    expect(panel).not_to_contain_text("响应符合登记条件")
    expect(button).to_be_disabled()
    if change == "scope":
        expect(disk).not_to_contain_text("a.example.test")
        expect(panel.locator("[data-nginx-dependencies-run]")).to_be_disabled()
    else:
        expect(disk).to_contain_text("a.example.test")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(loaded_generation="confirmed"),
        lambda value: value.update(binding_digest="a" * 64),
        lambda value: value.update(status="failed"),
        lambda value: value["checks"][0].update(raw_response=PRIVATE),
        lambda value: value["checks"][0].update(body_matches=False),
    ],
)
def test_route_observation_rejects_extra_unbound_or_inconsistent_evidence(console, mutation):
    page, contract = console(path=True)
    mutation(contract.path_value)
    panel = page.locator('[data-nginx-dependencies="fixture"] [data-nginx-path-observation]')
    panel.locator("[data-nginx-path-observation-run]").click()
    expect(panel).to_contain_text("本次路径响应未能核实")
    expect(panel).not_to_contain_text("响应符合登记条件")
    assert PRIVATE not in page.locator("body").inner_text()
