"""Real Chromium DOM; synthetic local contracts, no backend/SSH/provider I/O."""

import hashlib
import json
from pathlib import Path

import pytest
from browser_compose_discovery_smoke import CANDIDATE, PRIVATE, TOKEN, ComposeContract
from browser_platform_smoke import static_console
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ("web/app.js", "web/index.html", "web/styles.css")


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FRONTEND}


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(headless=True)
        yield instance
        instance.close()


@pytest.fixture
def console(browser, tmp_path):
    before = hashes()
    contexts, contracts = [], []
    with static_console() as base:

        def open_console(**options):
            contract = ComposeContract(**options)
            contract.base = base
            contracts.append(contract)
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            context.add_init_script(
                "Object.defineProperty(navigator,'clipboard',"
                "{value:{writeText:async value=>{window.composeCopied=value;}}});"
            )
            contexts.append(context)
            page = context.new_page()
            page.on("pageerror", lambda error: contract.errors.append(type(error).__name__))
            page.route("**/*", contract.route)
            page.goto(base)
            page.locator("#token-input").fill(TOKEN)
            page.locator("#login-button").click()
            expect(page.locator("#app-shell")).to_be_visible()
            page.locator('button[data-view="hosts"]').click()
            return page, contract

        yield open_console
    for context in contexts:
        context.close()
    after = hashes()
    record = {
        "schema": "opsark-compose-discovery-ui-contract/v1",
        "frontend_contract_only": True,
        "backend_or_remote_verified": False,
        "source_before": before,
        "source_after": after,
        "source_unchanged": before == after,
        "contracts": [contract.counts for contract in contracts],
    }
    with (tmp_path / "compose-ui.safe.json").open("x", encoding="ascii", newline="\n") as output:
        output.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
    assert before == after
    assert all(
        not contract.errors
        and not any(
            contract.counts[key]
            for key in ("forbidden_writes", "unexpected_routes", "external_requests")
        )
        for contract in contracts
    )


def section(page, host="compose-a"):
    return page.locator('[data-compose-host="' + host + '"]')


def select_candidate(panel):
    panel.locator("[data-compose-candidate]").select_option(CANDIDATE)
    expect(panel.locator("[data-compose-preview]")).to_be_disabled()
    assert panel.locator("[data-compose-port] option").all_text_contents() == [
        "请选择已观察端口",
        "18081",
    ]
    panel.locator("[data-compose-port]").select_option("18081")


@pytest.mark.parametrize("width", [320, 390, 768, 1440])
def test_explicit_discovery_tcp_choice_and_readonly_preview(console, tmp_path, width):
    page, contract = console()
    page.set_viewport_size({"width": width, "height": 900})
    assert contract.counts["discovery"] == contract.counts["preview"] == 0
    panel = section(page)
    expect(panel).to_contain_text("Nginx 关系未确认")
    panel.locator("[data-compose-discover]").click()
    select_candidate(panel)
    panel.locator("[data-compose-preview]").click()
    expect(panel.locator("[data-compose-fragment]")).to_contain_text(
        "expected_upstream_port = 18081"
    )
    expect(panel.locator("[data-compose-fragment]")).to_contain_text(
        "container_binding_confirmed = true"
    )
    expect(panel).to_contain_text("没有保存、重载、安装、补丁或业务复验")
    panel.get_by_role("button", name="复制候选登记片段", exact=True).click()
    assert "expected_upstream_port = 18081" in page.evaluate("window.composeCopied")
    assert contract.counts["discovery"] == contract.counts["preview"] == 1
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    page.screenshot(path=str(tmp_path / ("compose-" + str(width) + ".png")), full_page=True)


@pytest.mark.parametrize("enabled,configured", [(False, True), (True, False)])
def test_capability_and_private_project_scope_are_required(console, enabled, configured):
    page, contract = console(enabled=enabled, configured=configured)
    panel = section(page)
    if not enabled:
        expect(panel).to_have_count(0)
    else:
        expect(panel.locator("[data-compose-discover]")).to_be_disabled()
        expect(panel).to_contain_text("尚未配置授权 Compose 项目")
    assert contract.counts["discovery"] == contract.counts["preview"] == 0


@pytest.mark.parametrize(
    "mode,text",
    [
        ("empty", "未发现授权项目"),
        ("unavailable", "项目元数据已截断"),
        ("failure", "本次发现结果无法核实"),
    ],
)
def test_empty_and_failure_are_not_success_or_raw_output(console, mode, text):
    page, contract = console(mode=mode)
    panel = section(page)
    panel.locator("[data-compose-discover]").click()
    expect(panel).to_contain_text(text)
    expect(panel.locator("[data-compose-candidate]")).to_have_count(0)
    assert PRIVATE not in page.locator("body").inner_text()
    assert contract.counts["discovery"] == 1 and contract.counts["preview"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(raw_output=PRIVATE),
        lambda value: value.update(actions_enabled=True),
        lambda value: value.update(nginx_dependency="verified"),
        lambda value: value.update(snapshot_digest=PRIVATE),
        lambda value: value["candidates"][0].update(state=PRIVATE),
        lambda value: value["candidates"][0]["published_ports"][0].update(host_port=70000),
    ],
)
def test_unknown_or_out_of_bounds_discovery_is_rejected_whole(console, mutation):
    page, contract = console(mutation=mutation)
    panel = section(page)
    panel.locator("[data-compose-discover]").click()
    expect(panel).to_contain_text("本次发现结果无法核实")
    expect(panel.locator("[data-compose-candidate]")).to_have_count(0)
    assert PRIVATE not in page.locator("body").inner_text() and contract.counts["preview"] == 0


@pytest.mark.parametrize("mode", ["stale", "unsafe_preview"])
def test_preview_rejection_invalidates_candidates_without_automatic_rediscovery(console, mode):
    page, contract = console(mode=mode)
    panel = section(page)
    panel.locator("[data-compose-discover]").click()
    select_candidate(panel)
    panel.locator("[data-compose-preview]").click()
    expect(panel).to_contain_text("请重新发现")
    expect(panel.locator("[data-compose-candidate]")).to_have_count(0)
    expect(panel.locator("[data-compose-fragment]")).to_have_count(0)
    assert PRIVATE not in page.locator("body").inner_text()
    assert contract.counts["discovery"] == contract.counts["preview"] == 1


def test_no_tcp_candidate_cannot_preview(console):
    page, contract = console()
    panel = section(page)
    panel.locator("[data-compose-discover]").click()
    panel.locator("[data-compose-candidate]").select_option("b" * 64)
    expect(panel).to_contain_text("没有可登记的 TCP 宿主发布端口")
    expect(panel.locator("[data-compose-preview]")).to_have_count(0)
    assert contract.counts["preview"] == 0


def test_late_host_reply_is_never_rendered_on_other_card_or_after_logout(console):
    page, contract = console(hold=True)
    section(page).locator("[data-compose-discover]").click()
    expect(section(page).locator("[data-compose-discover]")).to_be_disabled()
    expect(section(page, "compose-b")).not_to_contain_text("synthetic-shop")
    page.locator("#logout-button").click()
    contract.release()
    expect(page.locator("#login-screen")).to_be_visible()
    assert "synthetic-shop" not in page.locator("body").inner_text()


@pytest.mark.parametrize(
    "project,container",
    [("", "manual-name"), ("synthetic-shop", "manual-name"), ("synthetic-shop", "")],
)
def test_onboarding_optional_project_is_omitted_or_sent_without_changing_pin_flow(
    console, project, container
):
    page, contract = console()
    page.locator("#host-onboarding > summary").click()
    values = {
        "host_id": "draft",
        "name": "Synthetic draft",
        "address": "192.0.2.31",
        "port": "22",
        "username": "opsark-readonly",
        "site_domain": "site.invalid",
        "container_name": container,
        "expected_upstream_port": "8081",
        "compose_project": project,
        "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAA",
        "expected_fingerprint": "SHA256:" + "A" * 43,
    }
    for name, value in values.items():
        page.locator('#host-onboarding-form [name="' + name + '"]').fill(value)
    page.locator("#host-onboarding-confirm").check()
    page.locator("#host-onboarding-prepare").click()
    expect(page.locator("#host-onboarding-result")).to_be_visible()
    body = next(call[2] for call in contract.calls if call[1] == "/api/host-onboarding/prepare")
    assert ("compose_project" in body) is bool(project)
    if project:
        assert body["compose_project"] == project
    assert ("container_name" in body) is bool(container)
    if not container:
        expect(page.locator("#host-onboarding-inventory")).to_have_value(
            '[[hosts]]\nid = "draft"\ncompose_project = "synthetic-shop"\n'
            "container_binding_confirmed = false\n"
        )
    assert body["expected_fingerprint"] == values["expected_fingerprint"]
    assert (
        contract.counts["onboarding"] == 1
        and contract.counts["discovery"] == contract.counts["preview"] == 0
    )


def test_pending_container_can_discover_and_preview_without_becoming_confirmed(console):
    page, contract = console(binding=False, preflight=True)
    card = page.locator('[data-host-id="compose-a"]')
    expect(card).to_contain_text("容器待确认")
    expect(card).not_to_contain_text("manual-name")
    card.locator("[data-host-preflight]").click()
    expect(card.locator('[data-check-id="container_state"]')).to_contain_text(
        "容器登记尚未确认，未读取容器状态或日志"
    )
    panel = section(page)
    panel.locator("[data-compose-discover]").click()
    select_candidate(panel)
    panel.locator("[data-compose-preview]").click()
    expect(panel.locator("[data-compose-fragment]")).to_contain_text(
        "container_binding_confirmed = true"
    )
    expect(card).to_contain_text("容器待确认")
    expect(card).to_contain_text("仍须部署者核对、应用登记并重新导出受限权限")
    assert contract.counts["discovery"] == contract.counts["preview"] == 1
    assert contract.counts["preflight"] == 1


@pytest.mark.parametrize("binding", [True, None])
def test_confirmed_and_legacy_container_display_is_preserved(console, binding):
    page, contract = console(binding=binding)
    card = page.locator('[data-host-id="compose-a"]')
    expect(card).to_contain_text("manual-name")
    expect(card).not_to_contain_text("容器待确认")
    assert contract.counts["discovery"] == contract.counts["preview"] == 0


def test_onboarding_missing_container_and_project_is_rejected_before_request(console):
    page, contract = console()
    page.locator("#host-onboarding > summary").click()
    values = {
        "host_id": "draft",
        "name": "Synthetic draft",
        "address": "192.0.2.31",
        "username": "opsark-readonly",
        "site_domain": "site.invalid",
        "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAA",
        "expected_fingerprint": "SHA256:" + "A" * 43,
    }
    for name, value in values.items():
        page.locator('#host-onboarding-form [name="' + name + '"]').fill(value)
    page.locator("#host-onboarding-confirm").check()
    page.locator("#host-onboarding-prepare").click()
    expect(page.locator("#host-onboarding-error")).to_contain_text("两项不能同时为空")
    assert contract.counts["onboarding"] == 0
