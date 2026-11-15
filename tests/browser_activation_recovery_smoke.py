"""Synthetic activation-backed pause recovery UI; no SSH, grants or real repair runs."""

import argparse
import copy
import json
from contextlib import suppress
from urllib.parse import urlsplit

from browser_activation_smoke import ACTIVATION, HOST, JOB
from browser_activation_smoke import Contract as ActivationContract
from browser_platform_smoke import static_console
from browser_remediation_smoke import NOW, UNTRUSTED, WIDTHS, stamp
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

RECOVERY = "8" * 32
DIGEST = "9" * 64
PREFIX = "/api/activation-recoveries"


class Contract(ActivationContract):
    def __init__(self, base_url, *, recovery_supported=True, mode="manual", fault=None):
        super().__init__(base_url, mode=mode)
        self.recovery_supported = recovery_supported
        self.recovery_enabled = True
        self.fault = fault
        self.parent_automatic = True
        self.paused = True
        self.eligible = True
        self.recovery_records = []
        self.recovery_prepares = []
        self.recovery_actions = []
        self.recovery_queries = []
        self.plan_mutation = None
        self.recovery_hold = None
        self.recovery_waiting = []
        self.jobs[(HOST, JOB)].update(
            authorization="automatic",
            install_exit_code=0,
            verification={"fresh_ssh": {"passed": True}},
        )
        self.records = [self.record("verified")]

    def remediation(self):
        self.jobs[(HOST, JOB)]["authorization"] = (
            "automatic" if self.parent_automatic else "assisted"
        )
        return super().remediation()

    def automatic(self):
        latch = {
            "host_id": HOST,
            "job_id": JOB,
            "reason": "installed_restart_pending",
            "latched_at": stamp(-300),
            "scope_hash": "d" * 64,
        }
        safety = {
            "schema_version": 1,
            "paused": self.paused,
            "reason": "automatic_job_installed_restart_pending" if self.paused else None,
            "job_id": JOB if self.paused else None,
            "updated_at": stamp(-300),
        }
        host = {
            "host_id": HOST,
            "name": "Synthetic automatically paused host",
            "scope_hash": "d" * 64,
            "state": "latched" if self.paused else "manual",
            "latch": latch if self.paused else None,
            "remote_status": {
                "host_id": HOST,
                "scope_hash": "d" * 64,
                "status": "available",
                "checked_at": stamp(),
                "remote": {"safety": safety, "usage": {"daily_used": 1, "total_used": 1}},
            },
            "quota": {"daily_used": 1, "daily_limit": 1, "total_used": 1, "total_limit": 1},
        }
        return {
            "enabled": False,
            "running": False,
            "mode": self.mode,
            "mode_revision": self.revision,
            "mode_sync_complete": True,
            "grants": [],
            "hosts": [host],
            "latched_hosts": [latch] if self.paused else [],
            "jobs": [],
            "notification_channel": "console",
        }

    def plan(self):
        value = {
            "schema_version": 1,
            "kind": "activation_recovery",
            "status": "activation_recovery_prepared",
            "host_id": HOST,
            "recovery_id": RECOVERY,
            "recovery_digest": DIGEST,
            "job_id": JOB,
            "job_revision": 7,
            "activation_id": ACTIVATION,
            "activation_revision": 6,
            "mode_revision": self.revision,
            "eligible": self.eligible,
            "checks": [
                {
                    "id": "verified_activation",
                    "status": "passed",
                    "detail": "Synthetic immutable native activation. " + UNTRUSTED,
                },
                {
                    "id": "runtime_complete",
                    "status": "passed" if self.eligible else "unavailable",
                    "detail": "Synthetic current mapping verification. " + UNTRUSTED,
                },
            ],
            "blockers": [] if self.eligible else ["runtime_complete"],
            "created_at": stamp(),
            "expires_at": stamp(300),
            "root_safety_before": {
                "schema_version": 1,
                "paused": True,
                "job_id": JOB,
                "reason": "automatic_job_installed_restart_pending",
                "updated_at": stamp(-300),
            },
            "verification": {"runtime": {"status": "complete", "outdated_process_count": 0}},
            "root_usage_before": {"daily_used": 1, "total_used": 1},
        }
        for field in (
            "job_digest",
            "activation_digest",
            "activation_record_digest",
            "activation_raw_sha256",
            "original_job_sha256",
            "original_plan_sha256",
            "runtime_manifest_sha256",
            "activation_plan_sha256",
            "restart_intent_sha256",
            "policy_digest",
            "driver_source_digest",
            "context_digest",
            "root_safety_digest",
            "root_safety_raw_sha256",
            "ledger_digest",
        ):
            value[field] = "a" * 64
        if self.plan_mutation:
            self.plan_mutation(value)
        return value

    def recovery_record(self, plan, status):
        value = {
            key: plan[key]
            for key in ("host_id", "job_id", "activation_id", "recovery_id", "recovery_digest")
        }
        value.update(
            schema_version=1,
            kind="activation_recovery",
            status=status,
            plan=copy.deepcopy(plan),
            local_released=status == "verified",
            stale=False,
            updated_at=stamp(),
            detail="Synthetic exact pause recovery. " + UNTRUSTED,
            receipt=None,
        )
        if status == "verified":
            receipt = {
                key: plan[key]
                for key in (
                    "schema_version",
                    "kind",
                    "host_id",
                    "job_id",
                    "activation_id",
                    "recovery_id",
                    "recovery_digest",
                    "context_digest",
                    "policy_digest",
                    "driver_source_digest",
                    "job_revision",
                    "job_digest",
                    "activation_revision",
                    "activation_digest",
                    "activation_record_digest",
                    "activation_raw_sha256",
                    "original_job_sha256",
                    "original_plan_sha256",
                    "runtime_manifest_sha256",
                    "activation_plan_sha256",
                    "restart_intent_sha256",
                    "root_safety_raw_sha256",
                    "ledger_digest",
                    "mode_revision",
                    "created_at",
                    "expires_at",
                )
            }
            receipt.update(
                status="verified",
                plan=copy.deepcopy(plan),
                receipt_digest="b" * 64,
                completed_at=stamp(1),
                resolved_safety_digest=plan["root_safety_digest"],
                checks=[{"id": "fresh_ssh", "status": "passed", "detail": "Synthetic"}],
                blockers=[],
                verification={
                    "fresh_ssh": {
                        "passed": True,
                        "mechanism": "sshd_connection_started_after_activation_recovery_preview",
                    },
                    "runtime": {"status": "complete", "outdated_process_count": 0},
                    **{
                        key: {"passed": True}
                        for key in (
                            "exact_package_version",
                            "vendor_rescan",
                            "health",
                            "activation_process",
                            "final_package_state",
                        )
                    },
                },
                resolved_job={
                    "status": "installed_restart_pending",
                    "job_id": JOB,
                    "revision": 7,
                    "job_digest": plan["job_digest"],
                },
                verified_activation={
                    "status": "verified",
                    "activation_id": ACTIVATION,
                    "revision": 6,
                    "activation_digest": plan["activation_digest"],
                    "record_digest": plan["activation_record_digest"],
                },
                safety_after={"paused": False, "job_id": None, "reason": None},
                root_usage_before=copy.deepcopy(plan["root_usage_before"]),
                root_usage_after=copy.deepcopy(plan["root_usage_before"]),
            )
            value["receipt"] = receipt
        return value

    def recovery_response(self, kind, route, value):
        if self.recovery_hold == kind:
            self.recovery_waiting.append((route, copy.deepcopy(value)))
        else:
            self.fulfill(route, value)

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if path == "/api/capabilities":
            self.fulfill(
                route,
                {
                    "mode": "read_only",
                    "automation_modes": True,
                    "vulnerability_remediation": True,
                    "service_activation": True,
                    "automatic_repair": True,
                    "automatic_recovery": False,
                    "activation_recovery": self.recovery_supported,
                },
            )
            return
        if path == "/api/automatic/status":
            self.requests.append((request.method, path))
            self.fulfill(route, self.automatic())
            return
        if not path.startswith(PREFIX):
            super().route(route)
            return
        assert self.recovery_supported
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        self.requests.append((request.method, path))
        if path == PREFIX and request.method == "GET":
            self.fulfill(
                route, {"enabled": self.recovery_enabled, "records": self.recovery_records}
            )
        elif path == PREFIX + "/plans":
            assert request.method == "POST"
            body = request.post_data_json
            assert body == {
                "host_id": HOST,
                "job_id": JOB,
                "activation_id": ACTIVATION,
                "expected_mode_revision": self.revision,
            }
            self.recovery_prepares.append(body)
            plan = self.plan()
            self.recovery_records = [self.recovery_record(plan, "prepared")]
            self.recovery_response("prepare", route, plan)
        elif path == PREFIX and request.method == "POST":
            body = request.post_data_json
            assert body == {
                "host_id": HOST,
                "recovery_id": RECOVERY,
                "expected_recovery_digest": DIGEST,
                "expected_mode_revision": self.revision,
                "confirm_recover": True,
            }
            self.recovery_actions.append(body)
            plan = self.recovery_records[0]["plan"]
            stored = self.recovery_record(
                plan, "unknown" if self.fault == "pending" else "verified"
            )
            self.recovery_records = [stored]
            response = copy.deepcopy(stored)
            if self.fault == "bad_anchor":
                response["activation_id"] = response["plan"]["activation_id"] = "f" * 32
                response["receipt"]["activation_id"] = "f" * 32
                response["receipt"]["verified_activation"]["activation_id"] = "f" * 32
                response["receipt"]["plan"]["activation_id"] = "f" * 32
            if self.fault == "false_release":
                response["local_released"] = False
            if self.fault == "failed_check":
                response["receipt"]["checks"][0]["status"] = "failed"
            if self.fault == "refunded_quota":
                response["receipt"]["root_usage_after"]["total_used"] = 0
            if self.fault == "missing_quota":
                del response["receipt"]["root_usage_after"]
            if self.fault == "abort":
                route.abort()
            else:
                self.recovery_response("submit", route, response)
        elif path == f"{PREFIX}/{HOST}/{RECOVERY}":
            self.recovery_queries.append(RECOVERY)
            if self.recovery_records[0]["status"] == "unknown":
                self.recovery_records = [
                    self.recovery_record(self.recovery_records[0]["plan"], "verified")
                ]
            self.recovery_response("query", route, self.recovery_records[0])
        else:
            self.failures.append("Unexpected activation recovery request")
            self.fulfill(route, {"detail": "Unknown synthetic route"}, 404)

    def release(self):
        super().release()
        self.recovery_hold = None
        for route, value in self.recovery_waiting:
            with suppress(Error):
                self.fulfill(route, value)
        self.recovery_waiting.clear()


def new_case(browser, base_url, *, width=1440, **options):
    context = browser.new_context(viewport={"width": width, "height": 1100})
    page = context.new_page()
    page.clock.install(time=NOW)
    contract = Contract(base_url, **options)
    page.route("**/*", contract.route)
    page.on("pageerror", lambda error: contract.failures.append(str(error)))
    login(page, base_url)
    page.locator("#remediation-nav").click()
    expect(page.locator("#remediation-host-select")).to_have_value(HOST)
    if contract.recovery_supported:
        expect(page.locator("#activation-recovery-summary")).to_contain_text(
            "当前入口仅接受手动模式"
        )
    return context, page, contract


def prepare(page):
    button = page.locator("[data-activation-recovery-prepare]")
    expect(button).to_be_enabled()
    button.click()
    expect(page.locator("#activation-recovery-dialog")).to_be_visible()


def approve(page):
    page.locator("#activation-recovery-confirm").check()
    expect(page.locator("#activation-recovery-execute")).to_be_enabled()
    page.locator("#activation-recovery-execute").click()


def safe(page, contract):
    assert not contract.failures and not contract.submissions and not contract.actions
    assert contract.jobs[(HOST, JOB)]["status"] == "installed_restart_pending"
    assert page.evaluate("window.remediationInjection === undefined")
    expect(page.locator("#activation-recovery-section img")).to_have_count(0)
    expect(page.locator("#activation-recovery-dialog img")).to_have_count(0)


def check_explicit_approval(browser, base_url):
    for width in WIDTHS:
        context, page, contract = new_case(browser, base_url, width=width)
        try:
            prepare(page)
            expect(page.locator("#activation-recovery-execute")).to_be_disabled()
            expect(page.locator("#activation-recovery-dialog-summary")).to_contain_text(JOB)
            expect(page.locator("#activation-recovery-dialog-summary")).to_contain_text(ACTIVATION)
            expect(page.locator("#activation-recovery-dialog-summary")).to_contain_text(DIGEST)
            expect(page.locator("#activation-recovery-dialog-summary")).to_contain_text(
                "手动 / 版本"
            )
            approve(page)
            expect(page.locator("#activation-recovery-detail")).to_contain_text(
                "这一条原暂停已完成独立对账"
            )
            assert len(contract.recovery_prepares) == len(contract.recovery_actions) == 1
            assert contract.mode == "manual"
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            safe(page, contract)
        finally:
            context.close()


def check_permissions_and_absent_feature(browser, base_url):
    for mode in ("assisted", "automatic"):
        context, page, contract = new_case(browser, base_url, mode=mode)
        try:
            expect(page.locator("[data-activation-recovery-prepare]")).to_be_disabled()
            assert not contract.recovery_prepares and not contract.recovery_actions
            safe(page, contract)
        finally:
            context.close()
    for field in ("parent_automatic", "paused", "recovery_enabled"):
        context, page, contract = new_case(browser, base_url)
        try:
            setattr(contract, field, False)
            page.locator("#refresh-remediation").click()
            page.locator("#refresh-automatic-repair").click()
            page.locator("#refresh-activation-recoveries").click()
            expect(page.locator("[data-activation-recovery-prepare]")).to_be_disabled()
            assert not contract.recovery_actions
            safe(page, contract)
        finally:
            context.close()
    context, page, contract = new_case(browser, base_url, recovery_supported=False)
    try:
        expect(page.locator("#activation-recovery-section")).not_to_be_visible()
        assert not any(path.startswith(PREFIX) for _, path in contract.requests)
        safe(page, contract)
    finally:
        context.close()


def check_unknown_and_resealed_responses(browser, base_url):
    for fault in (
        "abort",
        "bad_anchor",
        "false_release",
        "failed_check",
        "refunded_quota",
        "missing_quota",
    ):
        context, page, contract = new_case(browser, base_url, fault=fault)
        try:
            prepare(page)
            approve(page)
            expect(page.locator("#activation-recovery-error")).to_contain_text("已保留原恢复 ID")
            page.locator("#activation-recovery-records").get_by_role(
                "button", name="查询原恢复 " + RECOVERY
            ).click()
            expect(page.locator("#activation-recovery-detail")).to_contain_text(
                "这一条原暂停已完成独立对账"
            )
            assert len(contract.recovery_actions) == 1 and contract.recovery_queries == [RECOVERY]
            safe(page, contract)
        finally:
            context.close()


def check_expiry_mode_cancel_and_bad_preview(browser, base_url):
    for fault in ("cancel", "expiry", "mode", "pause", "blocked", "wrong_parent"):
        context, page, contract = new_case(browser, base_url)
        try:
            if fault == "blocked":
                contract.eligible = False
            if fault == "wrong_parent":
                contract.plan_mutation = lambda plan: plan.update(job_id="f" * 32)
                page.locator("[data-activation-recovery-prepare]").click()
                expect(page.locator("#activation-recovery-error")).to_contain_text("恢复预览")
                expect(page.locator("#activation-recovery-dialog")).not_to_be_visible()
            else:
                prepare(page)
                if fault == "cancel":
                    page.locator("#activation-recovery-cancel").click()
                elif fault == "expiry":
                    page.clock.fast_forward(300_001)
                elif fault == "mode":
                    page.evaluate(
                        "const e=document.querySelector('#automation-mode-select');"
                        "e.value='assisted';e.dispatchEvent(new Event('change'))"
                    )
                elif fault == "pause":
                    contract.paused = False
                    page.locator("#activation-recovery-confirm").check()
                    page.evaluate("document.querySelector('#refresh-automatic-repair').click()")
                else:
                    expect(page.locator("#activation-recovery-confirm")).to_be_disabled()
                if fault != "blocked":
                    expect(page.locator("#activation-recovery-dialog")).not_to_be_visible()
            assert not contract.recovery_actions
            safe(page, contract)
        finally:
            context.close()


def check_late_preview_and_persisted_query(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.recovery_hold = "prepare"
        page.locator("[data-activation-recovery-prepare]").click()
        page.locator("#remediation-host-select").select_option("synthetic-b")
        contract.release()
        expect(page.locator("#activation-recovery-dialog")).not_to_be_visible()
        assert len(contract.recovery_prepares) == 1 and not contract.recovery_actions
        safe(page, contract)
    finally:
        contract.release()
        context.close()
    for changed in ("host", "mode"):
        context, page, contract = new_case(browser, base_url)
        try:
            prepare(page)
            contract.recovery_hold = "submit"
            approve(page)
            expect(page.locator("#activation-recovery-progress")).to_contain_text("批准意图已固定")
            if changed == "host":
                page.locator("#remediation-host-select").select_option("synthetic-b")
            else:
                page.evaluate(
                    "const e=document.querySelector('#automation-mode-select');"
                    "e.value='assisted';e.dispatchEvent(new Event('change'))"
                )
            contract.release()
            expect(page.locator("#activation-recovery-progress")).to_have_text("")
            expect(page.locator("#activation-recovery-detail")).not_to_contain_text(
                "这一条原暂停已完成独立对账"
            )
            if changed == "host":
                page.locator("#remediation-host-select").select_option(HOST)
            else:
                page.evaluate(
                    "const e=document.querySelector('#automation-mode-select');"
                    "e.value='manual';e.dispatchEvent(new Event('change'))"
                )
            page.locator("#activation-recovery-records").get_by_role(
                "button", name="查询原恢复 " + RECOVERY
            ).click()
            expect(page.locator("#activation-recovery-detail")).to_contain_text(
                "这一条原暂停已完成独立对账"
            )
            assert len(contract.recovery_actions) == 1 and contract.recovery_queries == [RECOVERY]
            safe(page, contract)
        finally:
            contract.release()
            context.close()
    context, page, contract = new_case(browser, base_url, fault="pending")
    try:
        prepare(page)
        approve(page)
        expect(page.locator("#activation-recovery-detail")).to_contain_text("恢复结果未知")
        login(page, base_url)
        page.locator("#remediation-nav").click()
        expect(page.locator("[data-activation-recovery-query]")).to_be_visible()
        expect(page.locator("[data-activation-recovery-prepare]")).to_be_disabled()
        page.locator("[data-activation-recovery-query]").click()
        expect(page.locator("#activation-recovery-detail")).to_contain_text(
            "这一条原暂停已完成独立对账"
        )
        assert len(contract.recovery_actions) == 1 and contract.recovery_queries == [RECOVERY]
        safe(page, contract)
    finally:
        context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    args = parser.parse_args()
    with static_console() as base_url, sync_playwright() as p:
        browser = getattr(p, args.browser).launch(headless=True)
        try:
            check_explicit_approval(browser, base_url)
            check_permissions_and_absent_feature(browser, base_url)
            check_unknown_and_resealed_responses(browser, base_url)
            check_expiry_mode_cancel_and_bad_preview(browser, base_url)
            check_late_preview_and_persisted_query(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "synthetic_activation_recovery_groups": 5,
                        "widths": list(WIDTHS),
                        "real_ssh_or_recovery_actions": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
