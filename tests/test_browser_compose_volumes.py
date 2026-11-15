"""Browser rendering and late-response fencing with synthetic receipts."""

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from browser_compose_discovery_smoke import TOKEN, ComposeContract, launch_fixture_browser
from playwright.sync_api import expect, sync_playwright
from test_compose_volume_controller import host, response

from opsark.compose_volume_metadata import binding_digest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "mode", ["observed", "registration_changed", "unclassified", "across_volumes", "old_coverage"]
)
def test_compose_volume_card_shows_only_validated_observation(tmp_path, mode):
    target = host(tmp_path)
    scope, binding = target.compose_volume_scope_digest, binding_digest(target)
    original = target.public.model_dump(mode="json") | {
        "compose_volume_scope_digest": scope,
        "compose_volume_binding_digest": binding,
    }
    contract = ComposeContract()
    contract.base = "http://127.0.0.1:18489"
    host_reads = requests = 0

    def dispatch(route):
        nonlocal host_reads, requests
        path = urlsplit(route.request.url).path
        if not route.request.url.startswith(contract.base + "/"):
            return contract.route(route)
        if path == "/compose-volumes.js":
            return route.fulfill(
                content_type="text/javascript", body=(ROOT / "web/compose-volumes.js").read_bytes()
            )
        if path == "/api/hosts":
            host_reads += 1
            listing = (
                original
                if mode != "registration_changed" or host_reads == 1
                else original
                | {
                    "compose_volume_binding_digest": "0" * 64,
                }
            )
            return route.fulfill(json=[listing])
        if path == "/api/hosts/fixture/compose-volume-metadata":
            requests += 1
            assert route.request.method == "POST" and route.request.post_data_json == {}
            assert route.request.headers["authorization"] == "Bearer " + TOKEN
            data = response(target) | {
                "host_id": "fixture",
                "binding_digest": binding,
                "collected_at": datetime.now(UTC).isoformat(),
                "duration_ms": 42,
            }
            if mode == "unclassified":
                data["volumes"][0]["raw_volume_name"] = "synthetic-private-volume"
            if mode == "old_coverage":
                data["coverage"] = "compose_labeled_named_volumes"
            if mode == "across_volumes":
                data["observed_containers"] = 3
                data["volumes"].append(
                    {
                        "volume_ref": "d" * 32,
                        "sharing": "one_service",
                        "services": [{"service_ref": "e" * 32, "container_count": 2}],
                    }
                )
            return route.fulfill(content_type="application/json", body=json.dumps(data))
        return contract.route(route)

    with sync_playwright() as playwright:
        browser = launch_fixture_browser(playwright)
        page = browser.new_page(viewport={"width": 390, "height": 850}, service_workers="block")
        page.route("**/*", dispatch)
        page.goto(contract.base)
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#app-shell")).to_be_visible()
        page.locator('button[data-view="hosts"]').click()
        card = page.get_by_role("region", name="Compose 命名卷观察")
        card.get_by_role("button", name="观察命名卷共享").click()
        if mode == "observed":
            expect(card).to_contain_text("多个服务挂载")
            expect(card).to_contain_text("服务 1（1 个容器）")
            assert "a" * 32 not in card.inner_text()
        else:
            expect(card).to_contain_text("卷观察结果未能核实")
            expect(card).not_to_contain_text("多个服务挂载")
        assert "synthetic-private-volume" not in card.inner_text()
        assert card.get_by_role("button").count() == requests == 1
        assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
        browser.close()
    assert not any(
        contract.counts[key]
        for key in ("external_requests", "unexpected_routes", "forbidden_writes")
    )
