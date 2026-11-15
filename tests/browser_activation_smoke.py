"""Synthetic explicit service activation, immutable parent state and original-ID recovery."""

import argparse
import copy
import json
from contextlib import suppress
from urllib.parse import urlsplit

from browser_platform_smoke import static_console
from browser_remediation_smoke import NOW, UNTRUSTED, WIDTHS, scan_fixture, stamp
from browser_remediation_smoke import Contract as RemediationContract
from browser_security_smoke import TOKEN, login
from playwright.sync_api import Error, expect, sync_playwright

HOST = "synthetic-a"
JOB = "5" * 32
ACTIVATION = "6" * 32
DIGEST = "7" * 64
PREFIX = "/api/service-activations"


class Contract(RemediationContract):
    def __init__(self, base_url, *, mode="assisted", supported=True, result="verified"):
        super().__init__(base_url, mode=mode)
        self.supported = supported
        self.result = result
        self.eligible = True
        self.enabled = True
        self.preparations = []
        self.actions = []
        self.activation_queries = []
        self.records = []
        self.abort_response = False
        self.bad_binding = False
        self.bad_anchor = False
        self.fail_read = False
        self.scans = {HOST: scan_fixture(HOST), "synthetic-b": scan_fixture("synthetic-b")}
        self.jobs[(HOST, JOB)] = {
            "host_id": HOST,
            "job_id": JOB,
            "plan_id": "4" * 32,
            "status": "installed_restart_pending",
            "revision": 7,
            "notification_count": 1,
            "verification": {"runtime": {"status": "complete", "outdated_process_count": 1}},
        }

    def automation(self):
        value = super().automation()
        value["policy"]["service_activation"] = {
            "enabled": self.enabled,
            "host_ids": [HOST],
            "allowed_packages": ["demo-leaf"],
            "allowed_units": ["opsark-test.service"],
            "allow_critical_units": [],
            "max_services_per_activation": 1,
        }
        return value

    def record(self, status="prepared"):
        plan = {
            "activation_id": ACTIVATION,
            "activation_digest": DIGEST,
            "job_id": JOB,
            "original_job_status": "installed_restart_pending",
            "requires_reboot": False,
            "original_job_will_not_be_modified": True,
            "eligible": self.eligible,
            "blockers": [] if self.eligible else ["unit_identity"],
            "prepared_mode": self.mode,
            "mode_revision": self.revision,
            "unit": "opsark-test.service",
            "package": "demo-leaf",
            "candidate_version": "1.0-2",
            "processes": [{"pid": 42, "start_ticks": 1234}],
            "unit_evidence": {"configuration_digest": "a" * 64, "detail": UNTRUSTED},
            "created_at": stamp(),
            "expires_at": stamp(300),
        }
        return {
            "host_id": HOST,
            "activation_id": ACTIVATION,
            "activation_digest": DIGEST,
            "job_id": JOB,
            "status": status,
            "stale": False,
            "plan": plan,
            "updated_at": stamp(),
            "detail": "Synthetic original activation. " + UNTRUSTED,
            "result": {
                "status": "verified",
                "effective_result": "activation_verified",
                "original_job_unchanged": True,
                "original_safety_unchanged": True,
                "verification": {
                    "fresh_ssh": {"passed": True},
                    "runtime": {"status": "complete", "outdated_process_count": 0},
                },
            }
            if status == "verified"
            else None,
        }

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
                    "service_activation": self.supported,
                },
            )
            return
        if not path.startswith(PREFIX):
            super().route(route)
            return
        assert self.supported and request.headers.get("authorization") == "Bearer " + TOKEN
        self.requests.append((request.method, path))
        if path == PREFIX and request.method == "GET":
            self.fulfill(
                route,
                {
                    "enabled": self.enabled,
                    "records": self.records,
                    "original_patch_jobs_modified": False,
                },
            )
        elif path == PREFIX + "/plans":
            assert request.method == "POST"
            body = request.post_data_json
            assert body == {"host_id": HOST, "job_id": JOB, "expected_mode_revision": self.revision}
            self.preparations.append(body)
            self.records = [self.record()]
            self.respond("activation_prepare", route, self.records[0])
        elif path == PREFIX and request.method == "POST":
            body = request.post_data_json
            assert body == {
                "host_id": HOST,
                "activation_id": ACTIVATION,
                "expected_activation_digest": DIGEST,
                "expected_mode_revision": self.revision,
                "confirm_activate": True,
            }
            self.actions.append(body)
            self.records = [self.record(self.result)]
            response = copy.deepcopy(self.records[0])
            if self.bad_binding:
                response["job_id"] = "f" * 32
            if self.bad_anchor:
                response["job_id"] = response["plan"]["job_id"] = "f" * 32
                response["activation_digest"] = response["plan"]["activation_digest"] = "e" * 64
            if self.abort_response:
                route.abort()
            else:
                self.respond("activation_submit", route, response)
        elif path == f"{PREFIX}/{HOST}/{ACTIVATION}/evidence":
            self.fulfill(
                route,
                {
                    "schema_version": 1,
                    "kind": "synthetic-activation-evidence",
                    "identity": {"activation_id": ACTIVATION},
                },
            )
        elif path == f"{PREFIX}/{HOST}/{ACTIVATION}":
            self.activation_queries.append(ACTIVATION)
            self.fulfill(route, {"detail": "Read unavailable"}, 503) if self.fail_read else (
                self.respond("activation_query", route, self.records[0])
            )
        else:
            self.failures.append("Unexpected activation request")
            self.fulfill(route, {"detail": "Unknown route"}, 404)

    def release(self):
        self.hold = None
        for _, route, body, status in self.pending:
            with suppress(Error):
                self.fulfill(route, body, status)
        self.pending.clear()


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
    if contract.supported:
        expect(page.locator("#service-activation-summary")).to_contain_text("已登记独立激活范围")
        expect(page.locator("[data-service-activation-prepare]")).to_be_enabled() if (
            contract.mode in {"manual", "assisted"}
        ) else expect(page.locator("[data-service-activation-prepare]")).to_be_disabled()
    return context, page, contract


def prepare(page):
    page.locator("[data-service-activation-prepare]").click()
    expect(page.locator("#service-activation-dialog")).to_be_visible()


def execute(page):
    page.locator("#service-activation-confirm").check()
    expect(page.locator("#service-activation-execute")).to_be_enabled()
    page.locator("#service-activation-execute").click()


def safe(page, contract):
    assert not contract.failures and not contract.submissions
    assert contract.jobs[(HOST, JOB)]["status"] == "installed_restart_pending"
    assert page.evaluate("window.remediationInjection === undefined")
    expect(page.locator("#service-activation-section img")).to_have_count(0)
    expect(page.locator("#service-activation-dialog img")).to_have_count(0)


def check_explicit_approval(browser, base_url):
    for width in WIDTHS:
        context, page, contract = new_case(browser, base_url, width=width)
        try:
            assert not contract.preparations and not contract.actions
            prepare(page)
            expect(page.locator("#service-activation-execute")).to_be_disabled()
            expect(page.locator("#service-activation-dialog-summary")).to_contain_text(JOB)
            expect(page.locator("#service-activation-dialog-summary")).to_contain_text(
                "opsark-test.service"
            )
            execute(page)
            expect(page.locator("#service-activation-detail")).to_contain_text("本次激活验证通过")
            expect(page.locator("#service-activation-detail")).to_contain_text("没有被改写或解除")
            assert len(contract.preparations) == len(contract.actions) == 1
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            safe(page, contract)
        finally:
            context.close()


def check_no_implicit_permission(browser, base_url):
    for mode in ("manual", "automatic"):
        context, page, contract = new_case(browser, base_url, mode=mode)
        try:
            if mode == "manual":
                prepare(page)
                expect(page.locator("#service-activation-confirm")).to_be_disabled()
                expect(page.locator("#service-activation-execute")).to_be_disabled()
            assert not contract.actions
            safe(page, contract)
        finally:
            context.close()
    context, page, contract = new_case(browser, base_url, supported=False)
    try:
        expect(page.locator("#service-activation-section")).not_to_be_visible()
        assert not any(path.startswith(PREFIX) for _, path in contract.requests)
        safe(page, contract)
    finally:
        context.close()


def check_unknown_only_original_queries(browser, base_url):
    for fault in ("abort_response", "bad_binding", "bad_anchor"):
        context, page, contract = new_case(browser, base_url)
        try:
            setattr(contract, fault, True)
            prepare(page)
            execute(page)
            expect(page.locator("#service-activation-error")).to_contain_text("已保留原激活 ID")
            page.locator("#service-activation-detail").get_by_role(
                "button", name="查询原激活记录"
            ).click()
            expect(page.locator("#service-activation-detail")).to_contain_text("本次激活验证通过")
            assert len(contract.actions) == 1 and contract.activation_queries == [ACTIVATION]
            safe(page, contract)
        finally:
            context.close()


def check_drift_and_expiry(browser, base_url):
    for fault in ("mode", "expiry", "blocked"):
        context, page, contract = new_case(browser, base_url)
        try:
            if fault == "blocked":
                contract.eligible = False
            prepare(page)
            if fault == "mode":
                page.evaluate(
                    "const e=document.querySelector('#automation-mode-select');"
                    "e.value='manual';e.dispatchEvent(new Event('change'))"
                )
                expect(page.locator("#service-activation-dialog")).not_to_be_visible()
            elif fault == "expiry":
                page.clock.fast_forward(300_001)
                expect(page.locator("#service-activation-dialog")).not_to_be_visible()
            else:
                expect(page.locator("#service-activation-confirm")).to_be_disabled()
            assert not contract.actions
            safe(page, contract)
        finally:
            context.close()


def check_late_preview_does_not_restore_dialog(browser, base_url):
    context, page, contract = new_case(browser, base_url)
    try:
        contract.hold = "activation_prepare"
        page.locator("[data-service-activation-prepare]").click()
        page.locator("#remediation-host-select").select_option("synthetic-b")
        contract.release()
        expect(page.locator("#service-activation-dialog")).not_to_be_visible()
        assert len(contract.preparations) == 1 and not contract.actions
        safe(page, contract)
    finally:
        contract.release()
        context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    args = parser.parse_args()
    with static_console() as base_url, sync_playwright() as p:
        browser = getattr(p, args.browser).launch(headless=True)
        try:
            check_explicit_approval(browser, base_url)
            check_no_implicit_permission(browser, base_url)
            check_unknown_only_original_queries(browser, base_url)
            check_drift_and_expiry(browser, base_url)
            check_late_preview_does_not_restore_dialog(browser, base_url)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "synthetic_activation_groups": 5,
                        "widths": list(WIDTHS),
                        "real_ssh_or_service_actions": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
