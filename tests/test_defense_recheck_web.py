"""Synthetic HTTP/real Chromium defense recheck and safe customer export contracts."""

import json
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect
from test_defense_web import ACTION, TOKEN, Contract, confirm, stamp, transaction
from test_defense_web import browser as browser
from test_defense_web import console as console

from opsark.defense_handoff import (
    DefenseHandoffProjection,
    HandoffCheck,
    defense_handoff_markdown,
    merge_business,
    merge_verdict,
)
from opsark.defense_recheck_api import DefenseRecheckInterrupt, DefenseRecheckRequest
from opsark.defense_recheck_models import DefenseRecheckDeclaration

PROFILE = "e" * 64


def run_row(ref, sequence, statuses, *, current_unknown=False, incomplete=False, claimed=False):
    checks = tuple(
        HandoffCheck(
            number=number,
            status=status,
            reason_code={
                "passed": "matched",
                "failed": "status_mismatch",
                "inconclusive": "incomplete",
                "uncovered": "uncovered",
            }[status],
        )
        for number, status in enumerate(statuses, 1)
    )
    historical = merge_verdict(checks, bindings_complete=not incomplete)
    current = "pending" if current_unknown and historical == "passed" else historical
    original_bound = not incomplete and not claimed
    projection = DefenseHandoffProjection(
        original_authority_kind="human_approval" if original_bound else "unproven",
        original_authority_at=stamp(-7) if original_bound else None,
        execution_status="confirmed" if original_bound else "unproven",
        execution_submitted_at=stamp(-6) if original_bound else None,
        execution_confirmed_at=stamp(-4) if original_bound else None,
        receipt_status="unconfirmed" if current_unknown else "no_gap",
        receipt_unconfirmed_at=stamp() if current_unknown else None,
        reconciliation_status="pending" if current_unknown else "not_needed",
        historical_verdict="pending" if claimed else historical,
        current_verdict="pending" if claimed else current,
        business_verdict="pending" if claimed else merge_business(checks),
        authority_kind="unproven" if incomplete or claimed else "human_approval",
        root_before="unavailable" if claimed else "active",
        root_after="unavailable" if claimed else "expired",
        current_root="unknown" if current_unknown else "expired",
        transition="unknown" if claimed else "ttl_elapsed",
        started_at=stamp(-3),
        finished_at=None if claimed else stamp(-1),
        root_observed_at=None if claimed else stamp(-1),
        current_root_observed_at=stamp(),
        checks=() if claimed else checks,
        reasons=("result_unknown",)
        if claimed
        else ("original_profile_missing",)
        if incomplete
        else ("current_unknown",)
        if current_unknown
        else (),
    )
    return {
        "v": 2,
        "run_ref": ref,
        "host_id": "synthetic-a",
        "request_id": ACTION,
        "sequence": sequence,
        "status": "claimed" if claimed else "completed",
        "created_at": stamp(-4),
        "claimed_at": stamp(-3),
        "expected_manifest_sha256": "d" * 64,
        "expected_profile_sha256": PROFILE,
        "declaration_sha256": DefenseRecheckDeclaration(
            run_ref=ref,
            host_id="synthetic-a",
            rid=ACTION,
            expected_manifest_sha256="d" * 64,
            expected_profile_sha256=PROFILE,
        ).sha256,
        "can_interrupt": False,
        "historical_verdict": projection.historical_verdict,
        "current_verdict": projection.current_verdict,
        "projection": projection.model_dump(mode="json"),
    }


class RecheckContract(Contract):
    def __init__(self, *, retired=False, history_pages=False, incomplete=False):
        super().__init__(mode="manual", ai_required=False)
        self.rows[ACTION] = transaction("action", "active")
        self.retired, self.history_pages, self.incomplete = retired, history_pages, incomplete
        self.runs = {}
        self.next_statuses = ("passed", "passed", "passed")
        self.lose_next = False
        self.claim_only = False
        self.hold_export = False
        self.pending_export = None
        self.reject_export = False
        self.exports = []
        self.extra_history_ref = None
        self.legacy = {}

    def response(self, route, value):
        route.fulfill(content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        path, params = urlsplit(request.url).path, parse_qs(urlsplit(request.url).query)
        base = f"/api/hosts/synthetic-a/ssh-defense/transactions/{ACTION}"
        custom = path in {"/api/capabilities", "/api/ssh-defense/history-targets"}
        custom |= self.retired and path in {"/api/hosts", "/api/ssh-defense/status"}
        custom |= path.startswith(base + "/rechecks") or path == base + "/handoff"
        custom |= path.startswith(base + "/legacy-rechecks")
        custom |= path.startswith("/api/hosts/past-") and path.endswith("/ssh-defense/transactions")
        if not custom:
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        body = request.post_data_json if request.post_data else None
        self.calls.append((request.method, path, body))
        if path == "/api/capabilities":
            self.response(
                route,
                {
                    "mode": "read_only",
                    "automation_modes": True,
                    "ssh_defense_transactions": not self.retired,
                    "ssh_defense_history": True,
                    "ssh_defense_rechecks": True,
                    "security_observation": False,
                },
            )
        elif path == "/api/hosts":
            self.response(route, [])
        elif path == "/api/ssh-defense/status":
            self.response(
                route,
                {
                    "configured": False,
                    "enabled": False,
                    "disabled": True,
                    "mode": "manual",
                    "revision": 3,
                    "sync_generation": 1,
                    "mode_sync_complete": True,
                    "ai_required": False,
                    "targets": [],
                    "limited_profile": "private-198.18.241.0/28",
                    "ttl_ms": 60000,
                    "reason_code": "disabled",
                },
            )
        elif path == "/api/ssh-defense/history-targets":
            after = params.get("after", [None])[0]
            if self.history_pages and after is None:
                self.response(
                    route,
                    {
                        "history_targets": [{"host_id": f"past-{n:02d}"} for n in range(20)],
                        "next_after": "past-19",
                    },
                )
            else:
                self.response(
                    route, {"history_targets": [{"host_id": "synthetic-a"}], "next_after": None}
                )
        elif path.startswith("/api/hosts/past-"):
            self.response(route, {"transactions": []})
        elif path == base + "/rechecks" and request.method == "POST":
            declaration = DefenseRecheckRequest.model_validate(body)
            assert declaration.expected_manifest_sha256 == "d" * 64
            assert declaration.expected_profile_sha256 == PROFILE
            assert declaration.run_ref not in self.runs, "Duplicate POST for original recheck"
            row = run_row(
                declaration.run_ref,
                len(self.runs) + 1,
                self.next_statuses,
                incomplete=self.incomplete,
                claimed=self.claim_only,
            )
            self.runs[row["run_ref"]] = row
            if self.lose_next:
                self.lose_next = False
                route.abort("connectionreset")
            else:
                self.response(route, row)
        elif path == base + "/rechecks":
            after = int(params.get("after_sequence", ["0"])[0])
            limit = int(params.get("limit", ["20"])[0])
            rows = sorted(
                (row for row in self.runs.values() if row["sequence"] > after),
                key=lambda row: row["sequence"],
            )[:limit]
            active = next(
                (
                    row
                    for row in self.runs.values()
                    if row["status"] not in {"completed", "interrupted"}
                ),
                None,
            )
            self.response(
                route,
                {
                    "v": 2,
                    "host_id": "synthetic-a",
                    "request_id": ACTION,
                    "expected_manifest_sha256": "d" * 64,
                    "current_profile_sha256": PROFILE,
                    "configured_checks": 3,
                    "can_run": not self.retired and not active,
                    "active_run_ref": active["run_ref"] if active else None,
                    "active_request_id": ACTION if active else None,
                    "runs": rows,
                    "next_after_sequence": rows[-1]["sequence"] if len(rows) == limit else None,
                },
            )
        elif path.startswith(base + "/rechecks/") and path.endswith("/interrupt"):
            declaration = DefenseRecheckInterrupt.model_validate(body)
            ref = path.split("/")[-2]
            row = self.runs[ref]
            assert row["status"] == "claimed" and row["can_interrupt"] is True
            assert declaration.expected_declaration_sha256 == row["declaration_sha256"]
            projection = DefenseHandoffProjection(reasons=("interrupted",))
            row.update(
                status="interrupted",
                can_interrupt=False,
                historical_verdict="pending",
                current_verdict="pending",
                projection=projection.model_dump(mode="json"),
            )
            self.response(route, row)
        elif path.startswith(base + "/rechecks/"):
            self.response(route, self.runs[path.rsplit("/", 1)[-1]])
        elif path == base + "/legacy-rechecks":
            after = int(params.get("after_sequence", ["0"])[0])
            limit = int(params.get("limit", ["20"])[0])
            rows = sorted(
                (row for row in self.legacy.values() if row["sequence"] > after),
                key=lambda row: row["sequence"],
            )[:limit]
            self.response(
                route,
                {
                    "v": 1,
                    "host_id": "synthetic-a",
                    "request_id": ACTION,
                    "legacy_rechecks": rows,
                    "next_after_sequence": rows[-1]["sequence"] if len(rows) == limit else None,
                },
            )
        elif path.startswith(base + "/legacy-rechecks/"):
            ref = path.split("/")[-2] if path.endswith("/handoff") else path.rsplit("/", 1)[-1]
            row = self.legacy[ref]
            if path.endswith("/handoff"):
                text = defense_handoff_markdown(
                    DefenseHandoffProjection.model_validate_json(json.dumps(row["projection"]))
                )
                self.exports.append((ref, text))
                route.fulfill(content_type="text/markdown; charset=utf-8", body=text)
            else:
                self.response(route, row)
        elif path == base + "/handoff":
            if self.reject_export:
                route.fulfill(
                    status=503,
                    content_type="application/json",
                    body=json.dumps({"detail": "FAKE_SECRET_RAW_LOG_MUST_NOT_RENDER"}),
                )
                return
            ref = params.get("run_ref", [None])[0]
            projection = (
                DefenseHandoffProjection.model_validate_json(
                    json.dumps(self.runs[ref]["projection"])
                )
                if ref
                else DefenseHandoffProjection(reasons=("not_run",))
            )
            text = defense_handoff_markdown(projection)
            self.exports.append((ref, text))
            if self.hold_export:
                self.pending_export = route
            else:
                route.fulfill(content_type="text/markdown; charset=utf-8", body=text)


def select_original(page):
    page.locator(".ssh-defense-row").click()
    expect(page.get_by_role("button", name="刷新只读复验历史", exact=True)).to_be_visible()


def start_recheck(page):
    page.get_by_role("button", name="运行只读复验", exact=True).click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(ACTION)
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(PROFILE)
    confirm(page)


def verdict_card(page, label):
    return page.locator(".ssh-defense-verdict").filter(has_text=label)


def download_selected(page):
    label = "导出所选复验的安全摘要"
    with page.expect_download() as download:
        page.get_by_role("button", name=label, exact=True).click()
    assert download.value.suggested_filename == "opsark-defense-handoff.md"


def test_same_original_failed_timeout_recovery_and_old_report_exports(console):
    page, contract = console(_contract=RecheckContract)
    select_original(page)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    with page.expect_download():
        page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    assert "当前验收：待验收" in contract.exports[-1][1]
    contract.next_statuses = ("passed", "failed", "inconclusive")
    start_recheck(page)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("复验未通过")
    failed_ref = page.locator("[data-defense-recheck=selection]").input_value()
    download_selected(page)
    assert "复验未通过" in contract.exports[-1][1]
    contract.next_statuses = ("passed", "inconclusive", "passed")
    start_recheck(page)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    timeout_ref = page.locator("[data-defense-recheck=selection]").input_value()
    download_selected(page)
    assert "当前验收：待验收" in contract.exports[-1][1]
    contract.next_statuses = ("passed", "passed", "passed")
    start_recheck(page)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("登记业务复验通过")
    expect(page.locator(".ssh-defense-checks li[data-check-status=passed]")).to_have_count(3)
    passed_ref = page.locator("[data-defense-recheck=selection]").input_value()
    download_selected(page)
    assert "当前验收：登记业务复验通过" in contract.exports[-1][1]
    page.locator("[data-defense-recheck=selection]").select_option(failed_ref)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("复验未通过")
    download_selected(page)
    assert contract.exports[-1][0] == failed_ref
    page.locator("[data-defense-recheck=selection]").select_option(timeout_ref)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    page.locator("[data-defense-recheck=selection]").select_option(passed_ref)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("登记业务复验通过")
    assert contract.count("/rechecks") == 3
    assert contract.count("/apply") == contract.count("/prepare") == contract.count("/arm") == 0
    assert not any("/ai/" in path for _, path, _ in contract.calls)
    for _, text in contract.exports:
        assert "192.0.2." not in text and "fixture-a" not in text and "onerror" not in text
    assert not contract.errors


def test_lost_recheck_receipt_queries_same_ref_without_repost(console):
    page, contract = console(_contract=RecheckContract)
    select_original(page)
    contract.lose_next = contract.claim_only = True
    start_recheck(page)
    expect(page.locator(".ssh-defense-unresolved")).to_be_visible()
    expect(page.get_by_role("button", name="运行只读复验", exact=True)).to_be_disabled()
    ref = next(iter(contract.runs))
    assert page.locator("[data-defense-recheck=selection]").input_value() == ref
    assert contract.count("/rechecks") == 1
    contract.runs[ref] = run_row(ref, 1, ("passed", "passed", "passed"))
    page.get_by_role("button", name="查询当前选定复验", exact=True).click()
    expect(verdict_card(page, "所选历史验收")).to_contain_text("登记业务复验通过")
    assert contract.count("/rechecks") == 1
    assert any(
        path.endswith("/rechecks/" + ref) and method == "GET" for method, path, _ in contract.calls
    )
    assert contract.count("/apply") == 0
    assert not contract.errors


def test_all_checks_pass_without_complete_binding_stays_pending(console):
    page, contract = console(_contract=RecheckContract, incomplete=True)
    select_original(page)
    start_recheck(page)
    expect(verdict_card(page, "业务检查结果")).to_contain_text("登记业务复验通过")
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    expect(verdict_card(page, "本页读取时的当前验收")).to_contain_text("待验收")
    expect(page.locator(".ssh-defense-rechecks")).to_contain_text("原任务缺少业务检查快照")
    download_selected(page)
    assert "当前验收：待验收" in contract.exports[-1][1]
    assert not contract.errors


def test_history_pagination_preserves_old_selection_and_current_unknown(console):
    page, contract = console(_contract=RecheckContract)
    for sequence in range(1, 24):
        ref = f"{sequence:032x}"
        contract.runs[ref] = run_row(ref, sequence, ("passed", "passed", "passed"))
    select_original(page)
    first = f"{1:032x}"
    page.locator("[data-defense-recheck=selection]").select_option(first)
    page.get_by_role("button", name="下一页", exact=True).click()
    expect(page.locator(".ssh-defense-pagination")).to_contain_text("历史第 2 页")
    assert page.locator("[data-defense-recheck=selection]").input_value() == first
    download_selected(page)
    assert contract.exports[-1][0] == first
    newest = f"{23:032x}"
    contract.runs[newest] = run_row(
        newest, 23, ("passed", "passed", "passed"), current_unknown=True
    )
    page.locator("[data-defense-recheck=selection]").select_option(newest)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("登记业务复验通过")
    expect(verdict_card(page, "本页读取时的当前验收")).to_contain_text("待验收")
    page.get_by_role("button", name="上一页", exact=True).click()
    expect(page.locator(".ssh-defense-pagination")).to_contain_text("历史第 1 页")
    assert page.locator("[data-defense-recheck=selection]").input_value() == newest
    assert contract.count("/rechecks") == 0
    assert not contract.errors


def test_retired_history_only_target_can_export_without_remote_actions(console):
    page, contract = console(_contract=RecheckContract, retired=True)
    expect(page.locator('[data-defense="host"]')).to_contain_text("历史（未登记执行）")
    select_original(page)
    expect(page.get_by_role("button", name="查询同一个原任务", exact=True)).to_be_disabled()
    expect(page.locator('[data-defense="arm"]')).to_be_disabled()
    expect(page.get_by_role("button", name="运行只读复验", exact=True)).to_be_disabled()
    with page.expect_download():
        page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    assert not any(method == "POST" for method, _, _ in contract.calls)
    assert not contract.errors


def test_readonly_mode_change_cancels_confirmation_but_keeps_history(console):
    page, contract = console(_contract=RecheckContract)
    ref = "f" * 32
    contract.runs[ref] = run_row(ref, 1, ("passed", "failed", "passed"))
    select_original(page)
    page.locator("[data-defense-recheck=selection]").select_option(ref)
    page.get_by_role("button", name="运行只读复验", exact=True).click()
    page.locator('[data-defense="confirm"]').check()
    page.evaluate("document.querySelector('#refresh-automation').click()")
    expect(page.locator('[data-defense="dialog"]')).to_be_hidden()
    expect(verdict_card(page, "所选历史验收")).to_contain_text("复验未通过")
    expect(page.get_by_role("button", name="运行只读复验", exact=True)).to_be_enabled()
    assert contract.count("/rechecks") == 0
    download_selected(page)
    assert contract.exports[-1][0] == ref
    assert not contract.errors


def test_history_host_pagination_discovers_retired_target_with_no_current_hosts(console):
    page, contract = console(_contract=RecheckContract, retired=True, history_pages=True)
    expect(page.locator('[data-defense="host"]')).to_have_value("past-00")
    page.locator('[data-defense="history-targets"]').click()
    expect(page.locator('[data-defense="host"]')).to_contain_text("synthetic-a")
    page.locator('[data-defense="host"]').select_option("synthetic-a")
    select_original(page)
    expect(page.get_by_role("button", name="查询同一个原任务", exact=True)).to_be_disabled()
    with page.expect_download():
        page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    assert any(
        "after=past-19" in url
        for url in page.evaluate("performance.getEntriesByType('resource').map(e=>e.name)")
    )
    assert not any(method == "POST" for method, _, _ in contract.calls)
    assert not contract.errors


def test_late_export_after_host_change_does_not_download_or_bind_another_task(console):
    page, contract = console(_contract=RecheckContract)
    select_original(page)
    contract.hold_export = True
    downloads = []
    page.on("download", lambda download: downloads.append(download.suggested_filename))
    with page.expect_request(lambda request: urlsplit(request.url).path.endswith("/handoff")):
        page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    expect(page.locator('[data-defense="progress"]')).to_contain_text("正在导出")
    assert contract.pending_export is not None
    # Simulate target steering arriving while the older request remains in flight.
    page.evaluate(
        """() => {
            const host = document.querySelector('[data-defense=host]');
            host.value = 'synthetic-b';
            host.dispatchEvent(new Event('change', {bubbles:true}));
        }"""
    )
    contract.pending_export.fulfill(
        content_type="text/markdown; charset=utf-8", body="# Old summary"
    )
    expect(page.locator('[data-defense="progress"]')).to_contain_text("所选目标未登记事务专用凭据")
    assert not downloads
    expect(page.locator('[data-defense="detail"]')).not_to_contain_text(ACTION)
    assert not contract.errors


def test_export_error_does_not_show_raw_body_or_fallback_to_internal_report(console):
    page, contract = console(_contract=RecheckContract)
    select_original(page)
    contract.reject_export = True
    page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    expect(page.locator('[data-defense="error"]')).to_contain_text("导出安全交接摘要未确认")
    expect(page.locator("body")).not_to_contain_text("FAKE_SECRET_RAW_LOG_MUST_NOT_RENDER")
    assert not any("/reports/" in path for _, path, _ in contract.calls)
    assert not contract.errors


def test_only_server_offered_interrupt_closes_claim_and_new_run_stays_explicit(console):
    page, contract = console(_contract=RecheckContract)
    select_original(page)
    contract.claim_only = True
    start_recheck(page)
    ref = next(iter(contract.runs))
    expect(page.get_by_role("button", name="结束未完成只读复验", exact=True)).to_have_count(0)
    contract.runs[ref]["can_interrupt"] = True
    page.get_by_role("button", name="查询当前选定复验", exact=True).click()
    page.get_by_role("button", name="结束未完成只读复验", exact=True).click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(ref)
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(
        contract.runs[ref]["declaration_sha256"]
    )
    confirm(page)
    expect(page.locator(".ssh-defense-rechecks")).to_contain_text("复验已明确中断")
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    expect(page.get_by_role("button", name="运行只读复验", exact=True)).to_be_enabled()
    assert contract.count("/rechecks") == contract.count("/interrupt") == 1
    contract.claim_only = False
    start_recheck(page)
    new_ref = page.locator("[data-defense-recheck=selection]").input_value()
    assert new_ref != ref and contract.count("/rechecks") == 2
    page.locator("[data-defense-recheck=selection]").select_option(ref)
    expect(verdict_card(page, "所选历史验收")).to_contain_text("待验收")
    download_selected(page)
    assert contract.exports[-1][0] == ref
    assert "当前验收：待验收" in contract.exports[-1][1]
    assert contract.count("/apply") == contract.count("/prepare") == 0
    assert not contract.errors


def test_legacy_ids_use_separate_readonly_pending_only_history_and_export(console):
    page, contract = console(_contract=RecheckContract)
    for sequence in (1, 2):
        ref = f"{100 + sequence:032x}"
        projection = DefenseHandoffProjection(
            started_at=stamp(-30), finished_at=stamp(-20), reasons=("legacy_incomplete",)
        )
        contract.legacy[ref] = {
            "v": 1,
            "legacy_id": ref,
            "sequence": sequence,
            "host_id": "synthetic-a",
            "request_id": ACTION,
            "started_at": projection.started_at,
            "finished_at": projection.finished_at,
            "historical_verdict": "pending",
            "current_verdict": "pending",
            "projection": projection.model_dump(mode="json"),
        }
    select_original(page)
    page.locator(".ssh-defense-legacy summary").click()
    page.get_by_role("button", name="读取早期历史记录", exact=True).click()
    for ref in contract.legacy:
        page.locator("[data-defense-legacy=selection]").select_option(ref)
        expect(page.locator(".ssh-defense-legacy .badge")).to_have_text("待验收 · 早期证据不完整")
        with page.expect_download() as download:
            page.get_by_role("button", name="导出早期原记录摘要（待验收）", exact=True).click()
        assert download.value.suggested_filename == "opsark-defense-legacy-handoff.md"
        assert contract.exports[-1][0] == ref
        assert "当前验收：待验收" in contract.exports[-1][1]
        assert "不能作为业务验收通过" in contract.exports[-1][1]
    assert page.locator("[data-defense-recheck=selection]").input_value() == ""
    assert not any(method == "POST" for method, _, _ in contract.calls)
    assert not contract.errors
