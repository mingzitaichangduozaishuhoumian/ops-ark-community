"""Real app/loopback HTTP/Chromium; owned fake Root, credentials and business collector.

Action approval and its sole apply use the actual ASGI application before the UI
opens. All UI rechecks, history reads and Markdown downloads use real HTTP. The
one receipt-loss case forwards its exact POST to the real backend, then drops only
the browser HTTP acknowledgement. No API response is fabricated, and no real SSH,
model, deployment file, credential or database is consulted.
"""

import re
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Error, expect, sync_playwright
from test_defense_browser_application import serve
from test_defense_recheck_application import PREFIX, TOKEN, approved_action
from test_defense_recheck_application import application as application
from test_defense_recheck_application import keyset as keyset
from test_defense_recheck_application import main_module as main_module
from test_defense_recheck_application import target as target


@contextmanager
def browser_session(app):
    with serve(app) as base, sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Error as error:
            pytest.skip("Playwright Chromium unavailable: " + type(error).__name__)
        context = browser.new_context(viewport={"width": 1440, "height": 1100})
        page = context.new_page()
        errors, requests = [], []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.on("request", lambda request: requests.append((request.method, request.url)))
        try:
            yield SimpleNamespace(page=page, base=base, requests=requests, errors=errors)
            assert not errors
            assert all(
                url.startswith(base + "/") or url.startswith("blob:" + base + "/")
                for _, url in requests
            ), "The actual UI must not contact an external origin"
        finally:
            context.close()
            browser.close()


def open_original(h, rid):
    page = h.page
    page.goto(h.base)
    page.locator("#token-input").fill(TOKEN)
    page.locator("#login-form").evaluate("form => form.requestSubmit()")
    expect(page.locator("#app-shell")).to_be_visible()
    page.locator('button[data-view="security"]').click()
    original = page.locator('[data-defense="history"] .ssh-defense-row').filter(has_text=rid)
    expect(original).to_have_count(1)
    original.click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text(rid)
    expect(page.get_by_role("button", name="刷新只读复验历史", exact=True)).to_be_visible()


def verdict(h, label):
    return h.page.locator(".ssh-defense-verdict").filter(has_text=label)


def submit_readonly(h, rid):
    page = h.page
    page.get_by_role("button", name="运行只读复验", exact=True).click()
    dialog = page.locator('[data-defense="dialog"]')
    expect(dialog).to_be_visible()
    expect(dialog.locator('[data-defense="dialog-summary"]')).to_contain_text(rid)
    expect(dialog.locator('[data-defense="send"]')).to_be_disabled()
    dialog.locator('[data-defense="confirm"]').check()
    with page.expect_response(
        lambda response: (
            response.request.method == "POST"
            and urlsplit(response.url).path == PREFIX + "/transactions/" + rid + "/rechecks"
        )
    ) as response:
        dialog.locator('[data-defense="send"]').click()
    assert response.value.status == 200
    value = response.value.json()
    assert value["request_id"] == rid and value["status"] == "completed"
    assert re.fullmatch(r"[0-9a-f]{32}", value["run_ref"])
    expect(page.locator("[data-defense-recheck=selection]")).to_have_value(value["run_ref"])
    return value


def download_summary(h, tmp_path, filename, *, selected=True):
    label = "导出所选复验的安全摘要" if selected else "导出未复验摘要（待验收）"
    with h.page.expect_download() as downloaded:
        h.page.get_by_role("button", name=label, exact=True).click()
    assert downloaded.value.suggested_filename == "opsark-defense-handoff.md"
    destination = tmp_path / filename
    downloaded.value.save_as(destination)
    text = destination.read_text(encoding="utf-8")
    assert text.startswith("# OpsArk 防护任务交接摘要")
    for private in (
        TOKEN,
        "192.0.2.10",
        "synthetic-business.invalid",
        "source_ref",
        "key_file",
        "known_hosts_file",
        "-----BEGIN",
    ):
        assert private not in text
    return text


def assert_one_apply_and_no_new_mutations(root, rid):
    assert [(op, ref) for op, ref in root.sent if op == "apply"] == [("apply", rid)]
    assert sum(op == "prepare" for op, _ in root.sent) == 1
    assert sum(op == "arm" for op, _ in root.sent) == 1
    assert not any(op == "revoke" for op, _ in root.sent)


def test_actual_browser_rechecks_same_action_failure_timeout_recovery_and_old_exports(
    application, tmp_path
):
    app, client, root, _, outcomes, collections = application
    action = approved_action(application)
    rid = action["request_id"]
    changed = client.put("/api/automation", json={"mode": "manual", "expected_revision": 1})
    assert changed.status_code == 200 and changed.json()["mode"] == "manual"
    refs, downloaded = [], []
    with browser_session(app) as h:
        open_original(h, rid)
        expect(h.page.locator("#automation-mode-select")).to_have_value("manual")
        expect(verdict(h, "所选历史验收")).to_contain_text("待验收")
        before = download_summary(h, tmp_path, "before.md", selected=False)
        assert "当前验收：待验收" in before and not collections
        for index, (statuses, expected_status, label) in enumerate(
            (
                (["passed", "failed", "inconclusive"], "failed", "复验未通过"),
                (["passed", "passed", "inconclusive"], "pending", "待验收"),
                (["passed", "passed", "passed"], "passed", "登记业务复验通过"),
            ),
            1,
        ):
            outcomes[:] = statuses
            result = submit_readonly(h, rid)
            refs.append(result["run_ref"])
            assert result["historical_verdict"] == expected_status
            expect(verdict(h, "所选历史验收")).to_contain_text(label)
            expect(h.page.locator(".ssh-defense-checks li")).to_have_count(3)
            assert len(collections) == index
            text = download_summary(h, tmp_path, f"recheck-{index}.md")
            assert "当前验收：" + label in text
            assert rid not in text  # Public handover uses its own safe task-reference digest.
            downloaded.append(text)
            assert_one_apply_and_no_new_mutations(root, rid)
        assert len(set(refs)) == 3
        expect(h.page.locator(".ssh-defense-checks li[data-check-status=passed]")).to_have_count(3)
        for index, (ref, label) in enumerate(
            zip(refs, ("复验未通过", "待验收", "登记业务复验通过"), strict=True)
        ):
            h.page.locator("[data-defense-recheck=selection]").select_option(ref)
            expect(verdict(h, "所选历史验收")).to_contain_text(label)
            text = download_summary(h, tmp_path, f"old-{index}.md")
            assert "所选历史复验：" + label in text
        assert len(collections) == 3
        assert not any("/ai/" in urlsplit(url).path for _, url in h.requests)
        assert (
            sum(
                method == "POST" and urlsplit(url).path.endswith("/rechecks")
                for method, url in h.requests
            )
            == 3
        )
    assert len(collections) == 3 and len(downloaded) == 3
    assert_one_apply_and_no_new_mutations(root, rid)


def test_actual_browser_http_recheck_receipt_loss_recovers_original_run_without_repost(
    application, tmp_path
):
    app, _, root, _, outcomes, collections = application
    action = approved_action(application)
    rid = action["request_id"]
    outcomes[:] = ["passed", "passed", "passed"]
    intercepted = []
    with browser_session(app) as h:
        open_original(h, rid)
        path = PREFIX + "/transactions/" + rid + "/rechecks"

        def complete_then_drop_http_ack(route):
            assert route.request.method == "POST"
            body = route.request.post_data_json
            response = route.fetch(max_redirects=0, max_retries=0, timeout=10000)
            assert response.status == 200
            result = response.json()
            assert result["run_ref"] == body["run_ref"] and result["request_id"] == rid
            intercepted.append((body, result))
            route.abort("connectionreset")

        # This is the sole interception: the real backend executes the exact POST
        # once; only its HTTP acknowledgement to the browser is discarded.
        h.page.route(re.compile(re.escape(h.base + path) + r"$"), complete_then_drop_http_ack)
        h.page.get_by_role("button", name="运行只读复验", exact=True).click()
        dialog = h.page.locator('[data-defense="dialog"]')
        dialog.locator('[data-defense="confirm"]').check()
        dialog.locator('[data-defense="send"]').click()
        expect(verdict(h, "所选历史验收")).to_contain_text("登记业务复验通过")
        assert len(intercepted) == len(collections) == 1
        ref = intercepted[0][0]["run_ref"]
        expect(h.page.locator("[data-defense-recheck=selection]")).to_have_value(ref)
        assert any(
            method == "GET" and urlsplit(url).path in {path, path + "/" + ref}
            for method, url in h.requests
        )
        h.page.get_by_role("button", name="查询当前选定复验", exact=True).click()
        expect(verdict(h, "所选历史验收")).to_contain_text("登记业务复验通过")
        assert len(intercepted) == len(collections) == 1
        text = download_summary(h, tmp_path, "http-receipt-recovered.md")
        assert "当前验收：登记业务复验通过" in text
        assert not any("/ai/" in urlsplit(url).path for _, url in h.requests)
        assert_one_apply_and_no_new_mutations(root, rid)


def test_actual_browser_discovers_retired_history_without_current_hosts_or_transport(
    application, tmp_path
):
    app, client, root, _, _, collections = application
    action = approved_action(application)
    rid = action["request_id"]
    app.state.defense_service.targets.clear()
    hosts = app.state.defense_recheck_service.hosts
    assert isinstance(hosts, dict)
    hosts.clear()  # Owned fixture dictionary, also used by the app's current-host endpoint.
    assert not any(row["source"] == "ssh" for row in client.get("/api/hosts").json())
    before = tuple(root.sent)
    with browser_session(app) as h:
        open_original(h, rid)
        expect(h.page.locator('[data-defense="host"]')).to_contain_text("fixture")
        expect(h.page.locator('[data-defense="host"]')).to_contain_text("历史（未登记执行）")
        expect(h.page.locator('[data-defense="arm"]')).to_be_disabled()
        expect(h.page.get_by_role("button", name="查询同一个原任务", exact=True)).to_be_disabled()
        expect(h.page.get_by_role("button", name="运行只读复验", exact=True)).to_be_disabled()
        text = download_summary(h, tmp_path, "retired-pending.md", selected=False)
        assert "当前验收：待验收" in text
        assert not any(method == "POST" for method, _ in h.requests)
        assert tuple(root.sent) == before and not collections
