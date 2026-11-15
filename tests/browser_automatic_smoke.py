"""Synthetic browser contracts for preauthorized automatic repair visibility.

Run: uv run python tests/browser_automatic_smoke.py --browser chromium
No SSH, scanner, model, grant mutation or real patch execution is contacted.
"""

import argparse
import copy
import json
from contextlib import suppress
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from browser_platform_smoke import static_console
from browser_remediation_smoke import NOW, stamp
from browser_remediation_smoke import Contract as RemediationContract
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

UNTRUSTED = '<img src=x onerror="window.automaticInjection=true">'
WIDTHS = (1440, 1024, 768, 390, 320)
STATUS_PATH = "/api/automatic/status"
JOB = "a" * 32


def grant_fixture():
    return {
        "schema_version": 1,
        "enabled": True,
        "grant_id": "b" * 32,
        "issued_at": stamp(-3600),
        "expires_at": stamp(86400),
        "host_ids": ["synthetic-a"],
        "allowed_packages": ["demo-leaf", UNTRUSTED],
        "allowed_advisories": ["USN-9999-1"],
        "target_policy_digests": {"synthetic-a": "d" * 64},
        "maintenance_windows": [
            {"weekdays": [0, 1, 2, 3, 4], "start_minute": 1380, "end_minute": 60},
            {"weekdays": [5, 6], "start_minute": 0, "end_minute": 1440},
        ],
        "max_jobs_per_day": 1,
        "max_total_jobs": 1,
        "allowed_risk_levels": ["low", "medium"],
        "allow_service_restart": True,
        "grant_digest": "c" * 64,
    }


class Contract(RemediationContract):
    def __init__(self, base_url, *, supported=True, mode="automatic", watch_supported=False):
        super().__init__(base_url, mode=mode)
        self.supported = supported
        self.watch_supported = watch_supported
        self.enabled = True
        self.running = True
        self.synced = True
        self.grants = [grant_fixture()]
        self.host_state = "outside_window"
        self.window_open = False
        self.quota = {"daily_limit": 1, "daily_used": 0, "total_limit": 1, "total_used": 0}
        self.latch = None
        self.remote_status = None
        self.orphan_latches = []
        self.auto_jobs = []
        self.fail_status = False
        self.malformed = False
        self.auto_hold = False
        self.auto_pending = []
        self.auto_reads = []
        self.mode_puts = []
        self.mode_sync_error = False

    def automation(self):
        value = super().automation()
        value.update(
            supported_execution_modes=["assisted", "automatic"] if self.grants else ["assisted"],
            mode_sync_complete=self.synced,
            detail="合成执行驱动已配置；维护窗口和授权另行核对。",
        )
        return value

    def status(self):
        host = {
            "host_id": "synthetic-a",
            "name": "合成预授权目标 A",
            "scope_hash": "d" * 64,
            "state": self.host_state,
            "detail": UNTRUSTED,
            "last_checked": stamp(-10),
            "next_check": stamp(20),
            "maintenance_open": self.window_open,
            "grant_expires_at": self.grants[0]["expires_at"] if self.grants else None,
            "grant_digest": self.grants[0]["grant_digest"] if self.grants else None,
            "quota": self.quota,
            "current_job_id": JOB if self.latch or self.auto_jobs else None,
            "latch": self.latch,
            "remote_status": self.remote_status,
        }
        second = dict(
            host,
            host_id="synthetic-b",
            name="合成未授权目标 B",
            state="disabled",
            detail="未为此目标签发自动授权。",
            maintenance_open=None,
            grant_expires_at=None,
            grant_digest=None,
            quota=None,
            current_job_id=None,
            latch=None,
            remote_status=None,
        )
        return {
            "enabled": self.enabled,
            "running": self.running,
            "mode": self.mode,
            "mode_revision": self.revision,
            "mode_sync_complete": self.synced,
            "read_only": False,
            "notification_channel": "console",
            "last_error": None,
            "grants": self.grants,
            "hosts": [host, second],
            "latched_hosts": ([self.latch] if self.latch else []) + self.orphan_latches,
            "jobs": self.auto_jobs,
        }

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base_url + "/"):
            self.failures.append("Unexpected external browser destination")
            route.abort()
            return
        watch_paths = {"/api/vulnerability-watch/status", "/api/vulnerability-watch/alerts"}
        if path == "/api/automation" and request.method == "PUT":
            body = request.post_data_json
            self.mode_puts.append(body)
            if body == {"mode": self.mode, "expected_revision": self.revision}:
                self.requests.append((request.method, path))
                if request.headers.get("authorization") != "Bearer " + TOKEN:
                    self.failures.append("Mode sync did not carry console authentication")
                if self.mode_sync_error:
                    self.fulfill(route, {"detail": "合成模式同步失败"}, 503)
                else:
                    self.synced = True
                    self.fulfill(route, self.automation())
                return
        if path not in {"/api/capabilities", STATUS_PATH} | watch_paths:
            super().route(route)
            return
        self.requests.append((request.method, path))
        if request.headers.get("authorization") != "Bearer " + TOKEN:
            self.failures.append("Automatic state read did not carry console authentication")
        if request.method != "GET":
            self.failures.append("Automatic panel attempted a write")
        if path == "/api/capabilities":
            self.fulfill(
                route,
                {
                    "mode": "read_only",
                    "model_configured": False,
                    "ssh_hosts": 0,
                    "automation_modes": True,
                    "vulnerability_remediation": True,
                    "automatic_repair": self.supported,
                    "vulnerability_watch": self.watch_supported,
                    "security_observation": False,
                },
            )
            return
        if path in watch_paths:
            body = (
                {
                    "enabled": True,
                    "running": True,
                    "read_only": True,
                    "notification_channel": "console",
                    "interval_seconds": 3600,
                    "hosts": [],
                }
                if path.endswith("/status")
                else []
            )
            self.fulfill(route, body)
            return
        self.auto_reads.append((request.method, path))
        body, status = self.status(), 200
        if self.fail_status:
            body, status = {"detail": "合成自动状态读取失败"}, 503
        elif self.malformed:
            body["mode_revision"] = None
        if self.auto_hold:
            self.auto_pending.append((route, copy.deepcopy(body), status))
        else:
            self.fulfill(route, body, status)


def new_case(browser, base_url, *, ignore_abort=False, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.clock.install(time=NOW)
    if ignore_abort:
        page.add_init_script(
            "const nativeFetch=window.fetch;window.automaticSettled=0;"
            "window.fetch=(input,options={})=>"
            "nativeFetch.call(window,input,{...options,signal:undefined}).then(response=>{"
            "if(String(input)==='/api/automatic/status')queueMicrotask(()=>"
            "queueMicrotask(()=>window.automaticSettled++));return response;});"
        )
    contract = Contract(base_url, **options)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    page.route("**/*", contract.route)
    login(page, base_url)
    expect(page.locator("#automation-mode-select")).to_be_enabled()
    page.locator("#remediation-nav").click()
    if contract.supported:
        expect(page.locator(".automatic-repair-host")).to_have_count(2)
        expect(page.locator("#refresh-automatic-repair")).to_be_enabled()
    return context, page, contract


def safe(page, contract):
    assert not contract.failures, contract.failures
    assert not contract.scan_requests and not contract.plan_requests and not contract.submissions
    assert all(method == "GET" for method, _ in contract.auto_reads)
    assert page.evaluate("window.automaticInjection===undefined")
    expect(page.locator("#automatic-repair-section img")).to_have_count(0)
    expect(page.locator("#automatic-repair-section a")).to_have_count(0)


def refresh(page):
    page.locator("#refresh-automatic-repair").click()
    expect(page.locator("#refresh-automatic-repair")).to_be_enabled()


def release(contract):
    contract.auto_hold = False
    pending, contract.auto_pending = contract.auto_pending, []
    for route, body, status in pending:
        with suppress(Error):
            contract.fulfill(route, body, status)


def wait_pending(page, contract):
    deadline = monotonic() + 5
    while not contract.auto_pending and monotonic() < deadline:
        page.wait_for_timeout(20)
    assert contract.auto_pending, "Synthetic automatic status request was not held"


def check_scope_and_layout(browser, base_url, screenshots):
    context, page, contract = new_case(browser, base_url, watch_supported=True)
    try:
        first = page.locator('[data-automatic-host="synthetic-a"]')
        second = page.locator('[data-automatic-host="synthetic-b"]')
        expect(first).to_contain_text("等待 UTC 维护窗口")
        expect(first).to_contain_text("后台报告：窗口外")
        expect(second).to_contain_text("未获自动处置授权")
        expect(second).to_contain_text("未知 / 未知")
        expect(page.locator("#remediation-boundary")).not_to_contain_text("仅支持半自动")
        expect(page.locator("#vulnerability-watch-boundary-copy")).to_contain_text(
            "独立的自动处置后台另行核对预授权条件"
        )
        page.locator(".automatic-repair-grants > summary").click()
        grant = page.locator("#automatic-repair-grant-list")
        for text in (
            "demo-leaf",
            "USN-9999-1",
            "23:00 → 01:00 UTC",
            "次日结束，按开始日",
            "00:00 → 24:00 UTC",
            "开始含、结束不含",
            "中风险（可能影响服务）",
            "明确允许",
            "不自动执行",
            UNTRUSTED,
            "c" * 64,
        ):
            expect(grant).to_contain_text(text)
        expect(page.locator("#automatic-repair-summary")).to_contain_text(
            "后台运行只说明调度器状态"
        )
        expect(page.locator("#automatic-repair-summary")).to_contain_text(
            "未配置；此自动流程不调用模型"
        )
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"automatic-{width}.png"), full_page=True)
        safe(page, contract)
    finally:
        context.close()


def check_host_states(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        first = page.locator('[data-automatic-host="synthetic-a"]')
        for state, label in (
            ("expired", "预授权已到期"),
            ("quota_exhausted", "配额已用尽"),
            ("mode_unsynced", "等待模式同步"),
            ("waiting_scan", "等待有效扫描"),
            ("tracking", "正在追踪原任务"),
        ):
            contract.host_state = state
            refresh(page)
            expect(first).to_contain_text(label)
        contract.quota = {"daily_limit": 1, "daily_used": None}
        refresh(page)
        expect(first).to_contain_text("未知 / 1")
        contract.grants = []
        refresh(page)
        expect(first).to_contain_text("未获自动处置授权")
        expect(page.locator("#automatic-repair-summary > strong")).to_have_text(
            "已选择全自动 · 尚无预授权"
        )
        page.locator(".automatic-repair-grants > summary").click()
        expect(page.locator("#automatic-repair-grant-list")).to_contain_text("没有部署端预授权")
        safe(page, contract)
    finally:
        context.close()


def check_persistent_pause_and_modes(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.latch = {
            "host_id": "synthetic-a",
            "reason": "结果未知，必须核实原任务。" + UNTRUSTED,
            "job_id": JOB,
            "latched_at": stamp(-5),
        }
        contract.host_state = "latched"
        contract.orphan_latches = [
            {
                "host_id": "synthetic-previous",
                "reason": "旧目标原任务未核实，配置变更不清除暂停。",
                "job_id": "e" * 32,
                "latched_at": stamp(-60),
            }
        ]
        contract.auto_jobs = [
            {
                "host_id": "synthetic-a",
                "job_id": JOB,
                "package": "demo-leaf",
                "current_version": "1.0",
                "candidate_version": "1.1",
                "state": "tracking",
                "status": "unknown",
                "detail": UNTRUSTED,
                "updated_at": stamp(),
            }
        ]
        refresh(page)
        first = page.locator('[data-automatic-host="synthetic-a"]')
        expect(first).to_contain_text("持续暂停，保留原任务")
        expect(first).to_contain_text(JOB)
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("历史目标仍有持续暂停")
        expect(page.locator("#automatic-repair-hosts")).to_contain_text("e" * 32)
        for mode in ("manual", "assisted", "automatic"):
            page.locator("#automation-mode-select").select_option(mode)
            page.locator("#save-automation-mode").click()
            expect(page.locator("#automation-current")).to_contain_text(
                {"manual": "手动模式", "assisted": "半自动模式", "automatic": "全自动模式"}[mode]
            )
            expect(page.locator("#refresh-automatic-repair")).to_be_enabled()
            expect(first).to_contain_text("持续暂停，保留原任务")
            expect(first).to_contain_text(JOB)
        for status in ("unknown", "failed", "reboot_pending", "installed_restart_pending"):
            contract.auto_jobs[0]["status"] = status
            refresh(page)
            expect(first).to_contain_text("持续暂停，保留原任务")
            expect(page.locator("#automatic-repair-jobs")).to_contain_text(JOB)
        expect(page.locator("#automatic-repair-section button")).to_have_count(1)
        safe(page, contract)
    finally:
        context.close()


def check_disabled_and_legacy(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.enabled = False
        contract.running = False
        refresh(page)
        expect(page.locator("#automatic-repair-summary > strong")).to_have_text(
            "自动处置后台未启用"
        )
        safe(page, contract)
    finally:
        context.close()
    context, page, contract = new_case(browser, base_url, supported=False)
    try:
        expect(page.locator("#automatic-repair-section")).not_to_be_visible()
        page.clock.fast_forward(60001)
        assert not contract.auto_reads
        safe(page, contract)
    finally:
        context.close()


def check_root_cache_and_pause(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        first = page.locator('[data-automatic-host="synthetic-a"]')
        contract.host_state = "idle"
        refresh(page)
        expect(first).to_contain_text("远端 root 安全状态未核实")
        expect(first).not_to_contain_text("等待下一次后台检查")
        contract.remote_status = {
            "host_id": "synthetic-a",
            "scope_hash": "d" * 64,
            "policy_digest": "f" * 64,
            "checked_at": stamp(-5),
            "status": "available",
            "remote": {
                "enabled": True,
                "grant": grant_fixture(),
                "grant_digest": "c" * 64,
                "maintenance_open": True,
                "usage": {"daily_used": 1, "total_used": None},
                "safety": {
                    "schema_version": 1,
                    "paused": False,
                    "reason": None,
                    "job_id": None,
                    "updated_at": stamp(-6),
                },
            },
        }
        refresh(page)
        expect(first).to_contain_text("root 状态快照已缓存")
        expect(first).to_contain_text("1 / 未知")
        expect(first).to_contain_text("不超过 60 秒")
        contract.remote_status["status"] = "unavailable"
        contract.host_state = "error"
        refresh(page)
        expect(first).to_contain_text("后台条件未能核实")
        expect(first).to_contain_text("root 状态未能核实 · 保留历史快照")
        expect(first).not_to_contain_text("等待下一次后台检查")
        contract.remote_status["status"] = "available"
        contract.remote_status["remote"]["safety"].update(
            paused=True, reason="automatic_job_unknown", job_id=JOB
        )
        contract.host_state = "idle"
        refresh(page)
        expect(first).to_contain_text("已持续暂停 · 待核实")
        expect(first).to_contain_text("执行结果未知（automatic_job_unknown）")
        expect(first).to_contain_text("暂停来源：远端 root 持续记录")
        expect(first).to_contain_text(JOB)
        expect(first).not_to_contain_text("等待下一次后台检查")
        safe(page, contract)
    finally:
        context.close()


def check_failure_and_polling(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.fail_status = True
        refresh(page)
        expect(page.locator("#automatic-repair-error")).to_contain_text("历史快照不能证明")
        expect(page.locator("#automatic-repair-summary > strong")).to_contain_text("当前状态待核实")
        expect(page.locator(".automatic-repair-host").first).to_contain_text("历史快照")
        contract.fail_status = False
        contract.malformed = True
        refresh(page)
        expect(page.locator("#automatic-repair-error")).to_contain_text("缺少有效模式")
        contract.malformed = False
        before = len(contract.auto_reads)
        page.clock.fast_forward(30001)
        expect(page.locator("#automatic-repair-error")).not_to_be_visible()
        assert len(contract.auto_reads) > before
        page.locator('[data-view="capabilities"]').click()
        before = len(contract.auto_reads)
        page.clock.fast_forward(60001)
        assert len(contract.auto_reads) == before
        safe(page, contract)
    finally:
        context.close()


def check_late_logout(browser, base_url):
    context, page, contract = new_case(browser, base_url, ignore_abort=True)
    try:
        contract.auto_hold = True
        page.locator("#refresh-automatic-repair").click()
        wait_pending(page, contract)
        before = page.evaluate("window.automaticSettled")
        page.locator("#logout-button").click()
        release(contract)
        page.wait_for_function("before=>window.automaticSettled>before", arg=before)
        expect(page.locator("#automatic-repair-section")).not_to_be_visible()
        for identifier in (
            "automatic-repair-summary",
            "automatic-repair-hosts",
            "automatic-repair-grant-list",
            "automatic-repair-jobs",
        ):
            expect(page.locator("#" + identifier)).to_have_text("")
        before = len(contract.auto_reads)
        page.clock.fast_forward(60001)
        assert len(contract.auto_reads) == before
        safe(page, contract)
    finally:
        release(contract)
        context.close()


def check_resync_same_mode(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        page.locator('[data-view="capabilities"]').click()
        save = page.locator("#save-automation-mode")
        read = page.locator("#refresh-automation")
        current = page.locator("#automation-current")
        original_revision = contract.revision
        original_grants = copy.deepcopy(contract.grants)
        expect(save).to_be_disabled()
        contract.synced = False
        contract.mode_sync_error = True
        read.click()
        expect(save).to_have_text("重新同步")
        expect(save).to_be_enabled()
        assert not contract.mode_puts
        save.click()
        expect(page.locator("#automation-error")).to_contain_text("请重新读取")
        expect(save).to_be_disabled()
        contract.mode_sync_error = False
        read.click()
        expect(save).to_be_enabled()
        save.click()
        expect(save).to_be_disabled()
        expect(save).to_have_text("保存模式")
        expect(current).to_contain_text("全自动模式")
        expect(current).to_contain_text(str(original_revision))
        assert contract.mode_puts == [
            {"mode": "automatic", "expected_revision": original_revision},
            {"mode": "automatic", "expected_revision": original_revision},
        ]
        assert contract.revision == original_revision and contract.grants == original_grants
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
    with static_console() as base_url, sync_playwright() as playwright:
        browser = getattr(playwright, args.browser).launch(headless=True)
        try:
            check_scope_and_layout(browser, base_url, args.screenshots)
            check_host_states(browser, base_url)
            check_persistent_pause_and_modes(browser, base_url)
            check_disabled_and_legacy(browser, base_url)
            check_root_cache_and_pause(browser, base_url)
            check_failure_and_polling(browser, base_url)
            check_late_logout(browser, base_url)
            check_resync_same_mode(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_automatic_cases": 9,
                        "viewport_widths": list(WIDTHS),
                        "real_remote_or_model_calls": False,
                        "automatic_task_submissions": 0,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
