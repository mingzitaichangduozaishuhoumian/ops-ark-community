"""Synthetic browser contracts for scan, exact-plan consent and same-job recovery.

Run: uv run python tests/browser_remediation_smoke.py --browser chromium
All API responses are synthetic. No SSH host, model or provider is contacted.
"""

import argparse
import copy
import json
import re
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from browser_platform_smoke import static_console
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
FINDING = "a" * 64
PLAN = "b" * 32
DIGEST = "c" * 64
UNTRUSTED = '<img src=x onerror="window.remediationInjection=true">'
WIDTHS = (1440, 1024, 768, 390, 320)


def stamp(offset=0):
    return (NOW + timedelta(seconds=offset)).isoformat()


def scan_fixture(host):
    return {
        "host_id": host,
        "scan_id": "synthetic-partial-scan",
        "collected_at": stamp(),
        "inventory_digest": "1" * 64,
        "coverage": {"status": "partial", "packages_seen": 12, "packages_expected": 100},
        "gaps": ["合成覆盖缺口：供应商数据尚未覆盖全部已安装包。", UNTRUSTED],
        "findings": [
            {
                "finding_id": FINDING,
                "package": UNTRUSTED,
                "advisory": "USN-9999-1",
                "cve": ["CVE-SYNTHETIC-0001", UNTRUSTED],
                "current_version": "1.0-1ubuntu1",
                "fixed_binary_version": "1.0-1ubuntu2",
                "affected": True,
                "candidate_fixable": True,
                "vendor_evidence_fresh": True,
                "gaps": ["这条记录是合成证据，不是服务器检测结果。"],
            },
            {
                "finding_id": "2" * 64,
                "package": "synthetic-unknown",
                "advisory": UNTRUSTED,
                "current_version": "2.0-1ubuntu1",
                "affected": None,
                "candidate_fixable": False,
                "vendor_evidence_fresh": False,
                "gaps": ["受影响状态未知；缺失数据不能解释成安全。"],
            },
            {
                "finding_id": "3" * 64,
                "package": "synthetic-no-patch",
                "affected": True,
                "current_version": "3.0-1ubuntu1",
                "candidate_fixable": False,
                "vendor_evidence_fresh": True,
                "gaps": ["供应商尚无可用补丁。"],
            },
        ],
    }


class Contract:
    def __init__(self, base_url, *, mode="assisted", submit_result="unknown", hold=None):
        self.base_url = base_url
        self.mode = mode
        self.revision = 7
        self.submit_result = submit_result
        self.hold = hold
        self.pending = []
        self.failures = []
        self.requests = []
        self.scans = {"synthetic-a": None, "synthetic-b": None}
        self.jobs = {}
        self.scan_requests = []
        self.plan_requests = []
        self.submissions = []
        self.queries = []
        self.query_states = ["awaiting_transport_verification", "reboot_pending"]
        self.fail_query = False
        self.next_scan = None
        self.plan_revision = None
        self.plan_expiry = 600

    @staticmethod
    def fulfill(route, body, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    def respond(self, kind, route, body, status=200):
        if self.hold == kind:
            self.pending.append((kind, route, copy.deepcopy(body), status))
        else:
            self.fulfill(route, body, status)

    def automation(self):
        return {
            "mode": self.mode,
            "revision": self.revision,
            "modes": [
                {"id": name, "name": label, "description": "合成模式契约"}
                for name, label in (
                    ("manual", "手动模式"),
                    ("assisted", "半自动模式"),
                    ("automatic", "全自动模式"),
                )
            ],
            "execution_available": True,
            "supported_execution_modes": ["assisted"],
            "mode_sync_complete": True,
            "detail": "合成执行器仅开放半自动，不访问服务器。",
            "policy": {
                "enabled": True,
                "host_ids": list(self.scans),
                "allowed_actions": ["os_security_upgrade"],
                "allowed_packages": ["demo-leaf"],
                "max_packages_per_job": 1,
                "allow_reboot": False,
                "allow_service_restart": True,
            },
        }

    def remediation(self):
        return {
            "configured": True,
            "execution_available": True,
            "supported_execution_modes": ["assisted"],
            "detail": "纯合成修复契约，未执行真实安装。",
            "hosts": [
                {
                    "host_id": host,
                    "name": "合成目标 A" if host.endswith("a") else UNTRUSTED,
                    "scan": scan,
                }
                for host, scan in self.scans.items()
            ],
            "jobs": list(self.jobs.values()),
        }

    def plan(self, host):
        return {
            "schema_version": 1,
            "host_id": host,
            "plan_id": PLAN,
            "plan_digest": DIGEST,
            "state_digest": "4" * 64,
            "policy_digest": "5" * 64,
            "mode_revision": self.revision if self.plan_revision is None else self.plan_revision,
            "action": "os_security_upgrade",
            "created_at": stamp(),
            "expires_at": stamp(self.plan_expiry),
            "risk_level": "medium",
            "restart_assessment": "possible",
            "requires_service_restart": True,
            "requires_reboot": False,
            "package_changes": [
                {
                    "name": "demo-leaf",
                    "architecture": "amd64",
                    "current_version": "1.0-1ubuntu1",
                    "candidate_version": "1.0-1ubuntu3",
                    "fixed_version": "1.0-1ubuntu2",
                    "sha256": "6" * 64,
                }
            ],
            "health_before": {"passed": True, "detail": UNTRUSTED},
        }

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(self.base_url + "/"):
            self.failures.append("Unexpected external browser destination")
            route.abort()
            return
        if not path.startswith("/api/"):
            if path not in {
                "/",
                "/index.html",
                "/app.js",
                "/defense.js",
                "/nginx-dependencies.js",
                "/styles.css",
            }:
                self.failures.append("Unexpected local asset destination: " + path)
                route.abort()
            else:
                route.continue_()
            return
        self.requests.append((request.method, path))
        if path != "/api/status" and request.headers.get("authorization") != "Bearer " + TOKEN:
            self.failures.append("Protected synthetic request missing authentication")
        if path == "/api/status":
            self.fulfill(
                route, {"version": "synthetic-remediation-contract", "requires_auth": True}
            )
        elif path == "/api/capabilities":
            self.fulfill(
                route,
                {
                    "mode": "read_only",
                    "model_configured": False,
                    "ssh_hosts": 0,
                    "automation_modes": True,
                    "vulnerability_remediation": True,
                    "security_observation": False,
                },
            )
        elif path in {"/api/samples", "/api/hosts", "/api/reports"}:
            self.fulfill(route, [])
        elif path == "/api/automation":
            if request.method == "PUT":
                body = request.post_data_json
                if (
                    set(body) != {"mode", "expected_revision"}
                    or body["expected_revision"] != self.revision
                ):
                    self.fulfill(route, {"detail": "合成模式版本已变化"}, 409)
                    return
                self.mode = body["mode"]
                self.revision += 1
            self.fulfill(route, self.automation())
        elif path == "/api/remediation":
            self.respond("refresh", route, self.remediation())
        elif path == "/api/remediation/scans":
            body = request.post_data_json
            if (
                request.method != "POST"
                or set(body) != {"host_id"}
                or body["host_id"] not in self.scans
            ):
                self.failures.append("Unexpected scan authority")
            self.scan_requests.append(copy.deepcopy(body))
            scan = copy.deepcopy(self.next_scan or scan_fixture(body["host_id"]))
            self.scans[body["host_id"]] = scan
            self.respond("scan", route, scan)
        elif path == "/api/remediation/plans":
            body = request.post_data_json
            if request.method != "POST" or body != {
                "host_id": body.get("host_id"),
                "finding_id": FINDING,
            }:
                self.failures.append("Unexpected plan authority")
            self.plan_requests.append(copy.deepcopy(body))
            self.respond("plan", route, self.plan(body["host_id"]))
        elif path == "/api/remediation/jobs":
            body = request.post_data_json
            expected = {
                "host_id",
                "plan_id",
                "expected_plan_digest",
                "expected_mode_revision",
                "confirm_execute",
                "job_id",
            }
            if (
                request.method != "POST"
                or set(body) != expected
                or body["plan_id"] != PLAN
                or body["expected_plan_digest"] != DIGEST
                or body["expected_mode_revision"] != self.revision
                or body["confirm_execute"] is not True
                or not re.fullmatch(r"[0-9a-f]{32}", body["job_id"])
            ):
                self.failures.append("Submission was not bound to this exact approved plan")
            self.submissions.append(copy.deepcopy(body))
            job = {
                "host_id": body["host_id"],
                "job_id": body["job_id"],
                "plan_id": PLAN,
                "status": "unknown",
                "revision": 1,
                "history": [
                    {"status": "queued", "at": stamp(), "detail": UNTRUSTED},
                    {"status": "unknown", "at": stamp(1)},
                ],
                "verification": {"status": "not_run", "detail": UNTRUSTED},
            }
            self.jobs[(body["host_id"], body["job_id"])] = job
            if self.submit_result == "network_error":
                route.abort("failed")
            else:
                self.respond("submit", route, job, 202)
        elif path.startswith("/api/remediation/jobs/"):
            host, identifier = path.removeprefix("/api/remediation/jobs/").split("/")
            self.queries.append((host, identifier))
            if self.fail_query:
                self.fulfill(route, {"detail": "合成原任务查询暂不可用"}, 503)
                return
            if (host, identifier) not in self.jobs:
                self.failures.append("Queried a new identifier instead of the submitted job")
                self.fulfill(route, {"detail": "合成任务不存在"}, 404)
                return
            job = copy.deepcopy(self.jobs[(host, identifier)])
            status = self.query_states.pop(0) if self.query_states else "reboot_pending"
            job.update(
                status=status,
                revision=job["revision"] + 1,
                verification={"installed": True, "reboot_required": True, "detail": UNTRUSTED},
            )
            self.jobs[(host, identifier)] = job
            self.respond("query", route, job)
        else:
            self.failures.append("Unexpected API destination: " + path)
            self.fulfill(route, {"detail": "Unexpected synthetic endpoint"}, 404)


def new_case(browser, base_url, *, ignore_abort=False, **options):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.clock.install(time=NOW)
    if ignore_abort:
        # Exercise the session fence even if a fetch implementation ignores AbortSignal.
        page.add_init_script(
            "const nativeFetch=window.fetch;window.remediationSettled={};"
            "window.fetch=(input,options={})=>"
            "nativeFetch.call(window,input,{...options,signal:undefined}).then(response=>{"
            "const path=String(input);queueMicrotask(()=>queueMicrotask(()=>{"
            "window.remediationSettled[path]=(window.remediationSettled[path]||0)+1;"
            "}));return response;});"
        )
    contract = Contract(base_url, **options)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    page.route("**/*", contract.route)
    login(page, base_url)
    expect(page.locator("#automation-mode-select")).to_be_enabled()
    page.locator("#remediation-nav").click()
    expect(page.locator("#remediation-host-select")).to_have_value("synthetic-a")
    expect(page.locator("#run-remediation-scan")).to_be_enabled()
    return context, page, contract


def scan(page):
    page.locator("#run-remediation-scan").click()
    expect(page.locator(".remediation-finding")).to_have_count(3)


def prepare(page):
    page.locator('[data-remediation-finding="' + FINDING + '"]').click()
    expect(page.locator("#remediation-plan")).to_contain_text("demo-leaf")
    expect(page.locator("#review-remediation-plan")).to_be_visible()


def open_plan(page):
    page.locator("#review-remediation-plan").click()
    expect(page.locator("#remediation-dialog")).to_be_visible()
    expect(page.locator("#remediation-execute")).to_be_disabled()


def execute(page):
    page.locator("#remediation-confirm").check()
    page.locator("#remediation-execute").click()
    expect(page.locator("#remediation-dialog")).not_to_be_visible()


def safe_text(page, contract):
    expect(page.locator("#view-remediation img")).to_have_count(0)
    expect(page.locator("#remediation-dialog img")).to_have_count(0)
    assert page.evaluate("window.remediationInjection === undefined")
    assert not contract.failures, contract.failures


def check_scan_and_widths(browser, base_url, screenshots):
    context, page, contract = new_case(browser, base_url)
    try:
        assert not contract.scan_requests
        expect(page.locator("#remediation-scan-summary")).to_contain_text("尚无扫描记录")
        scan(page)
        expect(page.locator("#remediation-scan-summary")).to_contain_text("不证明整机无漏洞")
        expect(page.locator(".remediation-finding").nth(1)).to_contain_text("受影响状态未知")
        expect(page.locator(".remediation-finding").nth(1).get_by_role("button")).to_be_disabled()
        expect(page.locator(".remediation-finding").nth(2).get_by_role("button")).to_be_disabled()
        expect(page.locator("#remediation-findings")).to_contain_text(UNTRUSTED)
        page.locator("#remediation-scan-summary summary").click()
        expect(page.locator("#remediation-scan-summary")).to_contain_text('"status": "partial"')
        prepare(page)
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"), width
            if screenshots and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"remediation-{width}.png"), full_page=True)
        page.clock.fast_forward(1000)
        assert len(contract.scan_requests) == 1 and not contract.submissions
        safe_text(page, contract)
    finally:
        context.close()


def check_unknown_recovery(browser, base_url, submit_result):
    context, page, contract = new_case(browser, base_url, submit_result=submit_result)
    try:
        scan(page)
        prepare(page)
        open_plan(page)
        expect(page.locator("#remediation-dialog-summary")).to_contain_text("1.0-1ubuntu1")
        expect(page.locator("#remediation-dialog-summary")).to_contain_text("1.0-1ubuntu3")
        expect(page.locator("#remediation-dialog-summary")).to_contain_text(DIGEST)
        assert not contract.submissions
        execute(page)
        expect(page.locator("#query-remediation-job")).to_be_enabled()
        expect(page.locator("#remediation-job-detail")).to_contain_text("保留原任务，不重新安装")
        if submit_result == "network_error":
            expect(page.locator("#remediation-error")).to_contain_text("提交结果未确认")
        assert len(contract.submissions) == 1
        identifier = contract.submissions[0]["job_id"]
        assert re.fullmatch(r"[0-9a-f]{32}", identifier)
        expect(page.locator("#remediation-job-detail")).to_contain_text(identifier)
        expect(page.locator('[data-remediation-finding="' + FINDING + '"]')).to_be_disabled()
        page.evaluate("document.querySelector('#remediation-execute').click()")
        page.locator("#query-remediation-job").click()
        expect(page.locator("#remediation-job-detail")).to_contain_text("待验证新的管理连接")
        expect(page.locator("#remediation-job-detail")).to_contain_text("不能标记彻底修复")
        page.locator("#query-remediation-job").click()
        expect(page.locator("#remediation-job-detail")).to_contain_text("系统重启待处理")
        assert contract.queries == [("synthetic-a", identifier)] * 2
        contract.fail_query = True
        page.locator("#query-remediation-job").click()
        expect(page.locator("#remediation-error")).to_contain_text("没有查到记录也不能证明未安装")
        expect(page.locator("#remediation-job-detail")).to_contain_text("系统重启待处理")
        assert contract.queries == [("synthetic-a", identifier)] * 3
        page.clock.fast_forward(20000)
        assert len(contract.submissions) == 1
        safe_text(page, contract)
    finally:
        context.close()


def check_non_executing_mode(browser, base_url, mode):
    context, page, contract = new_case(browser, base_url, mode=mode)
    try:
        scan(page)
        prepare(page)
        expect(page.locator("#review-remediation-plan")).to_be_disabled()
        expect(page.locator("#remediation-boundary")).to_contain_text(
            "手动模式提供扫描和方案建议" if mode == "manual" else "不会因模式选择自动安装补丁"
        )
        page.clock.fast_forward(1000)
        assert not contract.submissions
        safe_text(page, contract)
    finally:
        context.close()


def check_invalidation(browser, base_url, reason):
    context, page, contract = new_case(browser, base_url)
    try:
        scan(page)
        prepare(page)
        open_plan(page)
        page.locator("#remediation-confirm").check()
        expect(page.locator("#remediation-execute")).to_be_enabled()
        if reason == "revision":
            contract.revision += 1
            page.evaluate("document.querySelector('#refresh-automation').click()")
        elif reason == "mode":
            page.evaluate(
                "const select=document.querySelector('#automation-mode-select');"
                "select.value='manual';select.dispatchEvent(new Event('change',{bubbles:true}));"
                "document.querySelector('#automation-mode-form').requestSubmit();"
            )
        elif reason == "target":
            page.evaluate(
                "const select=document.querySelector('#remediation-host-select');"
                "select.value='synthetic-b';"
                "select.dispatchEvent(new Event('change',{bubbles:true}));"
            )
        else:
            page.clock.fast_forward(601000)
        expect(page.locator("#remediation-dialog")).not_to_be_visible()
        expect(page.locator("#remediation-execute")).to_be_disabled()
        expect(page.locator("#review-remediation-plan")).to_have_count(0)
        if reason == "target":
            expect(page.locator("#remediation-host-select")).to_have_value("synthetic-b")
        else:
            expect(page.locator("#remediation-error")).to_contain_text(
                "模式" if reason in {"mode", "revision"} else "过期"
            )
        assert not contract.submissions
        safe_text(page, contract)
    finally:
        context.close()


def check_empty_partial_scan(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.next_scan = scan_fixture("synthetic-a") | {"findings": []}
        page.locator("#run-remediation-scan").click()
        expect(page.locator("#remediation-findings")).to_contain_text("本次覆盖范围未形成漏洞记录")
        expect(page.locator("#remediation-scan-summary")).to_contain_text("不证明整机无漏洞")
        expect(page.locator("#remediation-scan-summary")).to_contain_text("合成覆盖缺口")
        expect(page.locator(".remediation-finding")).to_have_count(0)
        expect(page.locator("#review-remediation-plan")).to_have_count(0)
        assert len(contract.scan_requests) == 1 and not contract.submissions
        safe_text(page, contract)
    finally:
        context.close()


def check_invalid_plan(browser, base_url, reason):
    context, page, contract = new_case(browser, base_url)
    try:
        scan(page)
        if reason == "revision":
            contract.plan_revision = contract.revision + 1
        else:
            contract.plan_expiry = -1
        page.locator('[data-remediation-finding="' + FINDING + '"]').click()
        expect(page.locator("#remediation-error")).to_contain_text("方案未就绪")
        expect(page.locator("#review-remediation-plan")).to_have_count(0)
        assert not contract.submissions
        safe_text(page, contract)
    finally:
        context.close()


def wait_pending(page, contract):
    deadline = monotonic() + 5
    while not contract.pending and monotonic() < deadline:
        page.wait_for_timeout(10)
    assert contract.pending, "Expected the synthetic request to be held before logout"


def release_pending(contract):
    for _kind, route, body, status in contract.pending:
        with suppress(Error):
            contract.fulfill(route, body, status)
    contract.pending.clear()


def check_late_logout(browser, base_url, operation):
    context, page, contract = new_case(browser, base_url, ignore_abort=True)
    try:
        if operation != "scan":
            scan(page)
        if operation in {"submit", "query"}:
            prepare(page)
        if operation == "scan":
            contract.hold = "scan"
            page.locator("#run-remediation-scan").click()
        elif operation == "plan":
            contract.hold = "plan"
            page.locator('[data-remediation-finding="' + FINDING + '"]').click()
        else:
            open_plan(page)
            if operation == "submit":
                contract.hold = "submit"
            execute(page)
            if operation == "query":
                expect(page.locator("#query-remediation-job")).to_be_enabled()
                contract.hold = "query"
                page.locator("#query-remediation-job").click()
        wait_pending(page, contract)
        held_path = urlsplit(contract.pending[0][1].request.url).path
        settled_before = page.evaluate("path=>window.remediationSettled[path]||0", held_path)
        page.locator("#logout-button").click()
        expect(page.locator("#login-screen")).to_be_visible()
        release_pending(contract)
        page.wait_for_function(
            "value=>(window.remediationSettled[value.path]||0)>value.before",
            arg={"path": held_path, "before": settled_before},
        )
        expect(page.locator("#remediation-findings")).to_have_text("")
        expect(page.locator("#remediation-plan")).to_have_text("")
        expect(page.locator("#remediation-job-detail")).to_have_text("")
        expect(page.locator("#remediation-dialog-summary")).to_have_text("")
        expect(page.locator("#app-shell")).not_to_be_visible()
        assert len(contract.submissions) == (1 if operation in {"submit", "query"} else 0)
        if operation == "submit":
            identifier = contract.submissions[0]["job_id"]
            contract.hold = None
            login(page, base_url)
            page.locator("#remediation-nav").click()
            page.locator('[data-remediation-job="' + identifier + '"]').click()
            expect(page.locator("#query-remediation-job")).to_be_enabled()
            assert contract.queries[-1] == ("synthetic-a", identifier)
            assert len(contract.submissions) == 1
        safe_text(page, contract)
    finally:
        release_pending(contract)
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
            check_scan_and_widths(browser, base_url, args.screenshots)
            check_empty_partial_scan(browser, base_url)
            for result in ("unknown", "network_error"):
                check_unknown_recovery(browser, base_url, result)
            for mode in ("manual", "automatic"):
                check_non_executing_mode(browser, base_url, mode)
            for reason in ("mode", "revision", "target", "expiry"):
                check_invalidation(browser, base_url, reason)
            for reason in ("revision", "expiry"):
                check_invalid_plan(browser, base_url, reason)
            for operation in ("scan", "plan", "submit", "query"):
                check_late_logout(browser, base_url, operation)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_remediation_cases": 16,
                        "viewport_widths": list(WIDTHS),
                        "real_remote_or_model_calls": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
