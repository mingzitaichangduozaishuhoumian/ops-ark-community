"""Synthetic, explicit human recovery controls; never contacts SSH or APT.

Run: uv run python tests/browser_recovery_smoke.py --browser chromium
"""

import argparse
import copy
import json
from contextlib import suppress
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from browser_automatic_smoke import JOB, UNTRUSTED, WIDTHS
from browser_automatic_smoke import Contract as AutomaticContract
from browser_platform_smoke import static_console
from browser_remediation_smoke import NOW, stamp
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

RECOVERY = "6" * 32
DIGEST = "7" * 64
HOST = "synthetic-a"
PREFIX = "/api/automatic/"


class Contract(AutomaticContract):
    def __init__(
        self, base_url, *, mode="manual", supported=True, result="verified", policy_override=None
    ):
        super().__init__(base_url, mode=mode)
        self.recovery_supported = supported
        self.result = result
        self.eligible = True
        self.latch = {
            "host_id": HOST,
            "job_id": JOB,
            "reason": "unknown" + UNTRUSTED,
            "scope_hash": "d" * 64,
            "latched_at": stamp(-300),
        }
        self.host_state = "latched"
        self.quota = {"daily_limit": 1, "daily_used": 1, "total_limit": 1, "total_used": 1}
        self.preparations = []
        self.recoveries = []
        self.recovery_queries = []
        self.records = []
        self.hold_recovery = None
        self.recovery_pending = []
        self.mutate_plan = None
        self.fail_recovery_status = False
        self.policy_override = policy_override or {}

    def automation(self):
        value = super().automation()
        value["policy"].update(self.policy_override)
        return value

    def plan_recovery(self):
        value = {
            "schema_version": 1,
            "status": "recovery_prepared",
            "host_id": HOST,
            "recovery_id": RECOVERY,
            "recovery_digest": DIGEST,
            "policy_digest": "d" * 64,
            "driver_source_digest": "e" * 64,
            "job_id": JOB,
            "job_revision": 7,
            "job_digest": "f" * 64,
            "mode_revision": self.revision,
            "context_digest": "8" * 64,
            "created_at": stamp(),
            "expires_at": stamp(300),
            "eligible": self.eligible,
            "checks": [
                {
                    "id": "original_job_verified",
                    "status": "passed",
                    "detail": "Original job is verified. " + UNTRUSTED,
                },
                {
                    "id": "runtime_complete",
                    "status": "passed" if self.eligible else "unavailable",
                    "detail": "The original runtime manifest is required. " + UNTRUSTED,
                },
            ],
            "blockers": [] if self.eligible else ["runtime_complete", UNTRUSTED],
            "verification": {
                "exact_package_version": {"expected": "1.1", "observed": "1.1", "passed": True},
                "health": {
                    "passed": True,
                    "services": [{"service": "ssh.service", "active": True}],
                    "http": [{"id": "lab", "status": 200, "passed": True}],
                },
                "runtime": {"status": "complete", "outdated_process_count": 0},
            },
        }
        if self.mutate_plan:
            self.mutate_plan(value)
        return value

    def record(self, plan, status):
        return {
            **{
                key: plan[key]
                for key in (
                    "host_id",
                    "recovery_id",
                    "recovery_digest",
                    "job_id",
                    "job_revision",
                    "job_digest",
                    "policy_digest",
                    "mode_revision",
                    "context_digest",
                )
            },
            "scope_hash": "d" * 64,
            "status": status,
            "plan": copy.deepcopy(plan),
            "latch_before": copy.deepcopy(self.latch),
            "receipt": {"status": status, "detail": UNTRUSTED} if status == "verified" else None,
            "local_released": status == "verified",
            "created_at": stamp(),
            "updated_at": stamp(),
            "confirmed_at": stamp() if status != "prepared" else None,
            "detail": "Synthetic recovery record; no SSH or package execution. " + UNTRUSTED,
        }

    def status(self):
        value = super().status()
        value["recoveries"] = copy.deepcopy(self.records)
        return value

    def respond_recovery(self, kind, route, body, status=200):
        if self.hold_recovery == kind:
            self.recovery_pending.append((route, copy.deepcopy(body), status))
        else:
            self.fulfill(route, body, status)

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if path == "/api/capabilities":
            self.requests.append((request.method, path))
            self.fulfill(
                route,
                {
                    "mode": "read_only",
                    "model_configured": False,
                    "ssh_hosts": 0,
                    "automation_modes": True,
                    "vulnerability_remediation": True,
                    "automatic_repair": True,
                    "automatic_recovery": self.recovery_supported,
                    "vulnerability_watch": False,
                    "security_observation": False,
                },
            )
            return
        if not path.startswith(PREFIX) or path == PREFIX + "status":
            super().route(route)
            return
        self.requests.append((request.method, path))
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        if path == PREFIX + "recovery-plans":
            body = request.post_data_json
            assert request.method == "POST"
            assert body == {"host_id": HOST, "job_id": JOB, "expected_mode_revision": self.revision}
            self.preparations.append(body)
            plan = self.plan_recovery()
            self.records = [self.record(plan, "prepared")]
            self.respond_recovery("prepare", route, plan)
            return
        if path == PREFIX + "recoveries" and request.method == "POST":
            body = request.post_data_json
            assert body == {
                "host_id": HOST,
                "recovery_id": RECOVERY,
                "expected_recovery_digest": DIGEST,
                "expected_mode_revision": self.revision,
                "confirm_recover": True,
            }
            self.recoveries.append(body)
            plan = self.records[0]["plan"]
            self.records = [self.record(plan, "unknown" if self.result == "abort" else self.result)]
            if self.result == "verified":
                self.latch = None
                self.host_state = "manual"
            if self.result == "abort":
                route.abort("failed")
            else:
                self.respond_recovery("submit", route, self.records[0])
            return
        if path == PREFIX + "recoveries":
            assert request.method == "GET"
            self.respond_recovery("list", route, self.records)
            return
        if path == PREFIX + "recoveries/" + HOST + "/" + RECOVERY:
            assert request.method == "GET"
            self.recovery_queries.append((request.method, path))
            if self.fail_recovery_status:
                self.fulfill(route, {"detail": "Synthetic query unavailable"}, 503)
            else:
                self.respond_recovery("query", route, self.records[0])
            return
        self.failures.append("Unexpected recovery route: " + path)
        route.abort()


def case(browser, base_url, *, ignore_abort=False, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.clock.install(time=NOW)
    if ignore_abort:
        page.add_init_script(
            "const nativeFetch=window.fetch;window.recoverySettled=0;"
            "window.fetch=(input,options={})=>nativeFetch.call(window,input,{...options,signal:undefined})"
            ".then(response=>{if(String(input).startsWith('/api/automatic/recover'))"
            "queueMicrotask(()=>queueMicrotask(()=>window.recoverySettled++));return response;});"
        )
    contract = Contract(base_url, **options)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    page.route("**/*", contract.route)
    login(page, base_url)
    page.locator("#remediation-nav").click()
    expect(page.locator("#refresh-automatic-repair")).to_be_enabled()
    if contract.recovery_supported:
        expect(page.locator("#automatic-recovery-section")).to_be_visible()
    return context, page, contract


def prepare(page):
    page.locator('[data-recovery-host="synthetic-a"]').click()
    expect(page.locator("#automatic-recovery-dialog")).to_be_visible()


def confirm(page):
    page.locator("#automatic-recovery-confirm").check()
    page.locator("#automatic-recovery-execute").click()
    expect(page.locator("#automatic-recovery-dialog")).not_to_be_visible()


def refresh(page):
    page.locator("#refresh-automatic-repair").click()
    expect(page.locator("#refresh-automatic-repair")).to_be_enabled()


def safe(page, contract):
    assert not contract.failures, contract.failures
    assert not contract.scan_requests and not contract.plan_requests and not contract.submissions
    assert page.evaluate("window.automaticInjection===undefined")
    expect(page.locator("#automatic-recovery-section img")).to_have_count(0)
    expect(page.locator("#automatic-recovery-dialog img")).to_have_count(0)


def wait_pending(page, contract):
    deadline = monotonic() + 5
    while not contract.recovery_pending and monotonic() < deadline:
        page.wait_for_timeout(20)
    assert contract.recovery_pending


def release(contract):
    contract.hold_recovery = None
    pending, contract.recovery_pending = contract.recovery_pending, []
    for route, body, status in pending:
        with suppress(Error):
            contract.fulfill(route, body, status)


def check_explicit_success(browser, base_url, screenshots):
    context, page, contract = case(browser, base_url)
    try:
        prepare(page)
        expect(page.locator("#automatic-recovery-execute")).to_be_disabled()
        expect(page.locator("#automatic-recovery-dialog-summary")).to_contain_text(JOB)
        expect(page.locator("#automatic-recovery-dialog-summary")).to_contain_text("1 / 1")
        expect(page.locator("#automatic-recovery-dialog-summary")).to_contain_text("当前实际版本")
        assert len(contract.preparations) == 1 and not contract.recoveries
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"recovery-{width}.png"), full_page=True)
                page.locator("#automatic-recovery-dialog").screenshot(
                    path=str(screenshots / f"recovery-dialog-{width}.png")
                )
        confirm(page)
        expect(page.locator("#automatic-recovery-records")).to_contain_text(
            "已完成核验并解除这次暂停"
        )
        expect(page.locator("#automatic-recovery-records")).to_contain_text("原暂停")
        expect(page.locator("#automatic-recovery-records")).to_contain_text(UNTRUSTED)
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("当前模式不执行自动处置")
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("1 / 1")
        assert contract.mode == "manual" and len(contract.recoveries) == 1
        safe(page, contract)
    finally:
        context.close()


def check_blocked_modes_and_preview(browser, base_url):
    for mode in ("automatic", "assisted"):
        context, page, contract = case(browser, base_url, mode=mode)
        try:
            expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
            assert not contract.preparations and not contract.recoveries
            safe(page, contract)
        finally:
            context.close()
    context, page, contract = case(browser, base_url)
    try:
        contract.eligible = False
        prepare(page)
        expect(page.locator("#automatic-recovery-dialog-summary")).to_contain_text("当前不能恢复")
        expect(page.locator("#automatic-recovery-dialog-summary")).to_contain_text(UNTRUSTED)
        expect(page.locator("#automatic-recovery-confirm")).to_be_disabled()
        expect(page.locator("#automatic-recovery-execute")).to_be_disabled()
        assert not contract.recoveries
        safe(page, contract)
    finally:
        context.close()


def check_unknown_and_reconnect(browser, base_url):
    context, page, contract = case(browser, base_url, result="abort")
    try:
        prepare(page)
        confirm(page)
        expect(page.locator("#automatic-recovery-records")).to_contain_text("恢复结果未知")
        expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
        assert len(contract.recoveries) == 1
        page.locator('[data-query-recovery="' + RECOVERY + '"]').click()
        expect(page.locator("#automatic-recovery-records")).to_contain_text("恢复结果未知")
        assert len(contract.recovery_queries) == 1 and len(contract.recoveries) == 1
        page.locator("#logout-button").click()
        login(page, base_url)
        page.locator("#remediation-nav").click()
        expect(page.locator("#automatic-recovery-records")).to_contain_text(RECOVERY)
        expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
        assert len(contract.recoveries) == len(contract.preparations) == 1
        contract.records[0]["status"] = "verified"
        contract.records[0]["local_released"] = True
        contract.records[0]["receipt"] = {"status": "verified"}
        contract.latch = None
        contract.host_state = "manual"
        page.locator('[data-query-recovery="' + RECOVERY + '"]').click()
        expect(page.locator("#automatic-recovery-records")).to_contain_text(
            "已完成核验并解除这次暂停"
        )
        assert len(contract.recoveries) == 1 and len(contract.recovery_queries) == 2
        assert contract.mode == "manual" and contract.quota["total_used"] == 1
        safe(page, contract)
    finally:
        context.close()


def check_rejected_expired_and_bad_plan(browser, base_url):
    context, page, contract = case(browser, base_url, result="rejected")
    try:
        prepare(page)
        confirm(page)
        expect(page.locator("#automatic-recovery-records")).to_contain_text("恢复被拒绝")
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("持续暂停，保留原任务")
        assert len(contract.recoveries) == 1
        safe(page, contract)
    finally:
        context.close()
    context, page, contract = case(browser, base_url)
    try:
        prepare(page)
        page.clock.fast_forward(300001)
        expect(page.locator("#automatic-recovery-dialog")).not_to_be_visible()
        expect(page.locator("#automatic-recovery-error")).to_contain_text("过期")
        assert not contract.recoveries
        safe(page, contract)
    finally:
        context.close()
    for mutation in (
        lambda p: p.update(job_id="9" * 32),
        lambda p: p.update(expires_at=stamp(301)),
        lambda p: p.update(created_at=stamp().replace("+00:00", "")),
    ):
        context, page, contract = case(browser, base_url)
        try:
            contract.mutate_plan = mutation
            page.locator('[data-recovery-host="synthetic-a"]').click()
            expect(page.locator("#automatic-recovery-error")).to_contain_text("未能核实")
            expect(page.locator("#automatic-recovery-dialog")).not_to_be_visible()
            assert not contract.recoveries
            safe(page, contract)
        finally:
            context.close()


def check_changed_context_and_late_logout(browser, base_url):
    context, page, contract = case(browser, base_url)
    try:
        contract.hold_recovery = "prepare"
        page.locator('[data-recovery-host="synthetic-a"]').click()
        wait_pending(page, contract)
        contract.mode = "automatic"
        contract.revision += 1
        refresh(page)
        release(contract)
        expect(page.locator("#automatic-recovery-error")).to_contain_text("变化")
        expect(page.locator("#automatic-recovery-dialog")).not_to_be_visible()
        assert not contract.recoveries
        safe(page, contract)
    finally:
        release(contract)
        context.close()
    context, page, contract = case(browser, base_url, ignore_abort=True)
    try:
        contract.hold_recovery = "prepare"
        page.locator('[data-recovery-host="synthetic-a"]').click()
        wait_pending(page, contract)
        before = page.evaluate("window.recoverySettled")
        page.locator("#logout-button").click()
        release(contract)
        page.wait_for_function("n=>window.recoverySettled>n", arg=before)
        expect(page.locator("#automatic-recovery-dialog")).not_to_be_visible()
        expect(page.locator("#automatic-recovery-dialog-summary")).to_have_text("")
        expect(page.locator("#automatic-recovery-records")).to_have_text("")
        assert not contract.recoveries
        safe(page, contract)
    finally:
        release(contract)
        context.close()


def check_legacy_and_failed_query(browser, base_url):
    context, page, contract = case(browser, base_url, supported=False)
    try:
        expect(page.locator("#automatic-recovery-section")).not_to_be_visible()
        expect(page.locator("[data-recovery-host]")).to_have_count(0)
        assert not contract.preparations and not contract.recoveries
        safe(page, contract)
    finally:
        context.close()


def check_partial_release_and_late_submit(browser, base_url):
    context, page, contract = case(browser, base_url, result="unknown")
    try:
        prepare(page)
        confirm(page)
        contract.records[0]["status"] = "verified"
        contract.records[0]["local_released"] = False
        refresh(page)
        expect(page.locator("#automatic-recovery-records")).to_contain_text("本地恢复状态仍待核实")
        expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
        assert len(contract.recoveries) == 1
        safe(page, contract)
    finally:
        context.close()
    context, page, contract = case(browser, base_url, ignore_abort=True)
    try:
        prepare(page)
        contract.hold_recovery = "submit"
        page.locator("#automatic-recovery-confirm").check()
        page.locator("#automatic-recovery-execute").click()
        wait_pending(page, contract)
        before = page.evaluate("window.recoverySettled")
        page.locator("#logout-button").click()
        release(contract)
        page.wait_for_function("n=>window.recoverySettled>n", arg=before)
        expect(page.locator("#automatic-recovery-records")).to_have_text("")
        expect(page.locator("#automatic-recovery-dialog-summary")).to_have_text("")
        login(page, base_url)
        page.locator("#remediation-nav").click()
        expect(page.locator("#automatic-recovery-records")).to_contain_text(
            "已完成核验并解除这次暂停"
        )
        assert len(contract.recoveries) == len(contract.preparations) == 1
        safe(page, contract)
    finally:
        release(contract)
        context.close()


def check_superseded_requires_new_explicit_review(browser, base_url):
    context, page, contract = case(browser, base_url, result="unknown")
    try:
        prepare(page)
        confirm(page)
        contract.records[0].update(
            status="superseded",
            local_released=False,
            receipt={"status": "verified", "recovery_id": RECOVERY},
            detail="The old receipt cannot resolve the changed pause.",
        )
        contract.latch["reason"] = "automatic_job_verification_failed"
        contract.latch["latched_at"] = stamp(1)
        refresh(page)
        expect(page.locator("#automatic-recovery-records")).to_contain_text(
            "上下文已变化，原恢复未解除当前暂停"
        )
        expect(page.locator("#automatic-recovery-records")).not_to_contain_text(
            "已完成核验并解除这次暂停"
        )
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("持续暂停，保留原任务")
        expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_enabled()
        assert len(contract.preparations) == len(contract.recoveries) == 1
        safe(page, contract)
    finally:
        context.close()


def check_disabled_policy_preserves_audit_without_preparing(browser, base_url):
    for policy in (
        {"enabled": False},
        {"allowed_actions": []},
        {"host_ids": ["synthetic-b"]},
    ):
        context, page, contract = case(browser, base_url, policy_override=policy)
        try:
            contract.records = [contract.record(contract.plan_recovery(), "prepared")]
            refresh(page)
            expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
            expect(page.locator("#automatic-repair-hosts")).to_contain_text(
                "当前部署未授权此目标的恢复入口"
            )
            expect(page.locator("#automatic-recovery-records")).to_contain_text(RECOVERY)
            assert not contract.preparations and not contract.recoveries
            safe(page, contract)
        finally:
            context.close()
    context, page, contract = case(browser, base_url, result="unknown")
    try:
        prepare(page)
        confirm(page)
        contract.fail_recovery_status = True
        page.locator('[data-query-recovery="' + RECOVERY + '"]').click()
        expect(page.locator("#automatic-recovery-error")).to_contain_text("不能据此判断未恢复")
        expect(page.locator('[data-recovery-host="synthetic-a"]')).to_be_disabled()
        assert len(contract.recoveries) == 1
        safe(page, contract)
    finally:
        context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with static_console() as base_url, sync_playwright() as p:
        browser = getattr(p, args.browser).launch(headless=True)
        try:
            check_explicit_success(browser, base_url, args.screenshots)
            check_blocked_modes_and_preview(browser, base_url)
            check_unknown_and_reconnect(browser, base_url)
            check_rejected_expired_and_bad_plan(browser, base_url)
            check_changed_context_and_late_logout(browser, base_url)
            check_legacy_and_failed_query(browser, base_url)
            check_partial_release_and_late_submit(browser, base_url)
            check_superseded_requires_new_explicit_review(browser, base_url)
            check_disabled_policy_preserves_audit_without_preparing(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_recovery_case_groups": 9,
                        "viewport_widths": list(WIDTHS),
                        "real_remote_or_package_calls": False,
                        "implicit_recovery_posts": 0,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
