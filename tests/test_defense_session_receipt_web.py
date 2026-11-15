"""Real Chromium and strict synthetic receipts; no SSH/provider or deployment data."""

import copy
import json
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect
from test_defense_session_web import REF, SessionContract, record, select_cursor
from test_defense_web import ACTION, ANALYSIS, CURSOR, TOKEN, confirm, stamp
from test_defense_web import browser as browser
from test_defense_web import console as console

OTHER_REF = "e" * 32
PRIVATE = "FAKE_SECRET_TOKEN_DATABASE_RAW_LOG_DO_NOT_DISPLAY"
RECEIPT_PATH = "/api/hosts/synthetic-a/ssh-defense/sessions/" + REF + "/ai-receipt"


def receipt(ref=REF, status="completed", *, usage="consumed", decision="propose_defense"):
    no_intent = status in {"not_required", "not_started"}
    return {
        "v": 1,
        "session_ref": ref,
        "analysis_id": None if no_intent else ANALYSIS,
        "status": status,
        "decision": decision if status == "completed" else None,
        "usage_state": None if no_intent else usage,
        "input_digest": None if no_intent else "1" * 64,
        "proof_sha256": "2" * 64
        if status == "completed" and decision == "propose_defense"
        else None,
        "actions_executable": False,
    }


class ReceiptContract(SessionContract):
    def __init__(
        self,
        *,
        receipt_status="completed",
        usage="consumed",
        change=None,
        hold=False,
        second=False,
        manual=True,
        ai_required=True,
        http_status=200,
    ):
        super().__init__(enabled=False, manual=manual, history=True, attached=True)
        self.ai_required = ai_required
        self.http_status = http_status
        self.session_rows[REF]["requires_ai"] = receipt_status != "not_required"
        self.receipt = receipt(status=receipt_status, usage=usage)
        if change:
            self.receipt.update(change)
        self.hold, self.pending = hold, None
        if second:
            self.session_rows[OTHER_REF] = record(OTHER_REF, "completed", owned=False)

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if path.endswith("/ai-receipt"):
            assert request.method == "GET" and request.post_data is None
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            self.calls.append((request.method, path, None))
            if self.hold:
                self.pending = route
                return
            body = copy.deepcopy(self.receipt)
            if path.endswith(OTHER_REF + "/ai-receipt"):
                body["session_ref"] = OTHER_REF
            route.fulfill(
                status=self.http_status,
                content_type="application/json",
                body=json.dumps(body if self.http_status == 200 else {"detail": PRIVATE}),
            )
            return
        if path.startswith("/api/hosts/synthetic-b/ssh-defense/sessions"):
            self.calls.append((request.method, path, None))
            assert path == "/api/hosts/synthetic-b/ssh-defense/sessions" and request.method == "GET"
            route.fulfill(
                content_type="application/json",
                body=json.dumps(
                    {
                        "v": 1,
                        "host_id": "synthetic-b",
                        "sessions": [],
                        "next_after_sequence": None,
                    }
                ),
            )
            return
        return super().route(route)


def open_original(page, ref=REF):
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.locator("button").filter(has_text=ref).click()
    return section.get_by_role("region", name="原 AI 安全回执", exact=True)


def writes(contract):
    return [call for call in contract.calls if call[0] not in {"GET", "HEAD"}]


@pytest.mark.parametrize("width", [320, 390, 768, 1440])
def test_original_receipt_is_explicit_get_only_and_fits_four_viewports(console, width, tmp_path):
    page, contract = console(_contract=ReceiptContract)
    page.set_viewport_size({"width": width, "height": 900})
    panel = open_original(page)
    assert not any(call[1].endswith("/ai-receipt") for call in contract.calls)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原分析已完成")
    expect(panel).to_contain_text("本地分析额度")
    expect(panel).to_contain_text("已占用")
    expect(panel).to_contain_text("不是提供方账单回执")
    expect(panel).to_contain_text("历史建议不作为新的执行依据")
    assert "已扣款" not in panel.inner_text() and "已付费" not in panel.inner_text()
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    assert writes(contract) == []
    assert [call for call in contract.calls if call[1].endswith("/ai-receipt")] == [
        ("GET", RECEIPT_PATH, None)
    ]
    assert not contract.errors
    if width == 320:
        page.screenshot(path=str(tmp_path / "session-receipt-mobile.png"), full_page=True)


@pytest.mark.parametrize(
    "status,copy",
    [
        ("not_required", "原策略不要求 AI，本次未调用"),
        ("not_started", "本次尚未登记 AI 调用"),
        ("unknown", "原分析结果未确认"),
        ("refused", "原分析未取得有效答复"),
        ("failed", "原分析失败"),
        ("stale", "原分析证据已失效"),
    ],
)
def test_historical_receipt_states_keep_unknown_and_no_intent_distinct(console, status, copy):
    page, contract = console(_contract=ReceiptContract, receipt_status=status, usage="unknown")
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text(copy)
    expect(panel).to_contain_text("尚无有效建议证明")
    if status in {"not_started", "not_required"}:
        expect(panel).to_contain_text("未登记调用意图")
    else:
        expect(panel).to_contain_text("保留未知")
    assert writes(contract) == [] and not contract.errors


@pytest.mark.parametrize(
    "change",
    [
        {"raw_log": PRIVATE},
        {"status": PRIVATE},
        {"input_digest": PRIVATE},
        {"proof_sha256": PRIVATE},
        {"actions_executable": True},
        {"session_ref": OTHER_REF},
        {"usage_state": None},
        {"analysis_id": None},
        {"status": "unknown"},
        {"decision": "no_action"},
    ],
)
def test_invalid_or_sensitive_receipt_is_rejected_as_a_whole(console, change):
    page, contract = console(_contract=ReceiptContract, change=change)
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原 AI 回执暂时无法核实")
    expect(panel).not_to_contain_text("原分析已完成")
    assert PRIVATE not in page.locator("body").inner_text()
    assert writes(contract) == [] and not contract.errors


@pytest.mark.parametrize("status", [409, 503])
def test_original_receipt_http_failure_never_displays_error_body(console, status):
    page, contract = console(_contract=ReceiptContract, http_status=status)
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原 AI 回执暂时无法核实")
    assert PRIVATE not in page.locator("body").inner_text()
    assert writes(contract) == [] and not contract.errors


def test_refreshing_invalid_receipt_drops_previous_success_and_partial_fields(console):
    page, contract = console(_contract=ReceiptContract)
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原分析已完成")
    contract.receipt["input_digest"] = PRIVATE
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原 AI 回执暂时无法核实")
    expect(panel).not_to_contain_text("原分析已完成")
    expect(panel).not_to_contain_text("2" * 64)
    assert PRIVATE not in page.locator("body").inner_text()
    assert writes(contract) == [] and not contract.errors


@pytest.mark.parametrize("usage,label", [("reserved", "已预留"), ("unknown", "保留未知")])
def test_original_local_usage_does_not_claim_provider_payment(console, usage, label):
    page, contract = console(_contract=ReceiptContract, usage=usage, receipt_status="unknown")
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text(label)
    expect(panel).to_contain_text("不是提供方账单回执")
    assert "已扣款" not in panel.inner_text() and writes(contract) == []


def test_late_original_receipt_cannot_cross_host_or_reappear_after_return(console):
    page, contract = console(_contract=ReceiptContract, hold=True)
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("正在读取原回执")
    page.locator('[data-defense="host"]').select_option("synthetic-b")
    expect(page.get_by_role("region", name="原 AI 安全回执", exact=True)).to_have_count(0)
    assert contract.pending is not None
    contract.pending.fulfill(content_type="application/json", body=json.dumps(contract.receipt))
    page.wait_for_timeout(80)
    assert "原分析已完成" not in page.locator("body").inner_text()
    contract.hold = False
    page.locator('[data-defense="host"]').select_option("synthetic-a")
    panel = open_original(page)
    expect(panel).not_to_contain_text("原分析已完成")
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原分析已完成")
    assert not any(
        "synthetic-b" in call[1] and call[1].endswith("/ai-receipt") for call in contract.calls
    )
    assert writes(contract) == [] and not contract.errors


def test_late_receipt_for_previous_selected_session_is_discarded(console):
    page, contract = console(_contract=ReceiptContract, hold=True, second=True)
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("正在读取原回执")
    panel = open_original(page, OTHER_REF)
    contract.pending.fulfill(content_type="application/json", body=json.dumps(contract.receipt))
    page.wait_for_timeout(80)
    expect(panel).not_to_contain_text("原分析已完成")
    contract.hold = False
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("原分析已完成")
    assert writes(contract) == [] and not contract.errors


def test_historical_ai_receipt_never_satisfies_current_manual_prepare_proof(console):
    class AssistedContract(ReceiptContract):
        def __init__(self):
            super().__init__(manual=False)
            self.mode = "assisted"

    page, contract = console(_contract=AssistedContract)
    select_cursor(page)
    page.locator('[name="ssh-defense-source"]:enabled').check()
    panel = open_original(page)
    panel.get_by_role("button", name="读取原 AI 安全回执", exact=True).click()
    expect(panel).to_contain_text("建议固定处置")
    expect(page.get_by_role("button", name="准备处置清单（不执行）", exact=True)).to_be_disabled()
    assert writes(contract) == [] and not contract.errors


@pytest.mark.parametrize(
    "remaining,owned,missing,root_offset",
    [
        (0, True, False, 7 * 3600),
        (110000, False, False, 110),
        (110000, True, True, 110),
        (1.5, True, False, 110),
    ],
)
def test_unverified_old_owner_or_expired_controller_window_disables_without_writes(
    console, remaining, owned, missing, root_offset
):
    class WindowContract(SessionContract):
        def __init__(self):
            super().__init__()
            self.rows[CURSOR]["current_result"]["deadline_at"] = stamp(root_offset)
            self.rows[CURSOR]["controller_observation"] = {
                "owned_by_current_boot": owned,
                "deadline_at": stamp(110),
                "remaining_ms": remaining,
            }
            if missing:
                del self.rows[CURSOR]["controller_observation"]

    page, contract = console(_contract=WindowContract)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    expect(section.get_by_role("button", name="启动这一次防护会话", exact=True)).to_be_disabled()
    expect(section.get_by_role("region", name="本地启动条件", exact=True)).to_contain_text(
        "Root 最终准入"
    )
    assert writes(contract) == [] and not contract.errors


def test_root_utc_does_not_replace_controller_countdown_and_timer_expires_without_poll(console):
    class WindowContract(SessionContract):
        def __init__(self):
            super().__init__()
            self.rows[CURSOR]["current_result"]["deadline_at"] = stamp(-7 * 3600)
            self.rows[CURSOR]["controller_observation"] = {
                "owned_by_current_boot": True,
                "deadline_at": stamp(110),
                "remaining_ms": 1800,
            }

    page, contract = console(_contract=WindowContract)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    start = section.get_by_role("button", name="启动这一次防护会话", exact=True)
    expect(start).to_be_enabled()
    before = len([call for call in contract.calls if "/sessions" in call[1]])
    expect(start).to_be_disabled(timeout=3000)
    expect(section).to_contain_text("原观察窗口已到期")
    assert len([call for call in contract.calls if "/sessions" in call[1]]) == before
    assert writes(contract) == [] and not contract.errors


@pytest.mark.parametrize(
    "issue,label",
    [
        ("disabled", "由部署者启用单次会话"),
        ("mode", "先保存全自动模式"),
        ("ack", "重新读取模式与事务状态"),
        ("observation", "本地观察许可未就绪"),
        ("execution", "本地执行许可未就绪"),
        ("unknown", "存在未知原任务"),
        ("submitted", "此原观察已提交会话"),
        ("owner", "当前进程仅能读取原会话"),
        ("worker", "单次会话后台未运行"),
    ],
)
def test_local_readiness_explains_disabled_start_without_writes(console, issue, label):
    class ConditionContract(SessionContract):
        def __init__(self):
            super().__init__(
                enabled=issue != "disabled", manual=issue == "mode", history=issue == "submitted"
            )
            if issue == "ack":
                self.synchronized = False
            if issue == "unknown":
                self.rows[ACTION]["query_required"] = True

        def route(self, route):
            original = route
            path = urlsplit(route.request.url).path
            if path in {"/api/ssh-defense/status", "/api/ssh-defense/sessions/status"}:

                class StatusRoute:
                    request = original.request

                    def fulfill(self, **options):
                        value = json.loads(options["body"])
                        if path == "/api/ssh-defense/status" and issue in {
                            "observation",
                            "execution",
                        }:
                            value["targets"][0][issue + "_available"] = False
                        if path == "/api/ssh-defense/sessions/status":
                            if issue == "owner":
                                value["mutation_owner"] = False
                            if issue == "worker":
                                value["running"] = False
                        options["body"] = json.dumps(value)
                        original.fulfill(**options)

                return super().route(StatusRoute())
            return super().route(route)

    page, contract = console(_contract=ConditionContract)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    expect(section.get_by_role("button", name="启动这一次防护会话", exact=True)).to_be_disabled()
    expect(section.get_by_role("region", name="本地启动条件", exact=True)).to_contain_text(label)
    assert writes(contract) == [] and not contract.errors


def test_window_expiring_inside_confirmation_does_not_submit_new_session(console):
    class WindowContract(SessionContract):
        def __init__(self):
            super().__init__()
            self.rows[CURSOR]["controller_observation"]["remaining_ms"] = 1500

    page, contract = console(_contract=WindowContract)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    page.wait_for_timeout(1700)
    confirm(page)
    expect(page.locator('[data-defense="dialog"]')).not_to_be_visible()
    expect(page.locator('[data-defense="progress"]')).to_contain_text("未提交新会话")
    assert writes(contract) == [] and not contract.errors


def test_window_read_time_deducts_round_trip_instead_of_restarting_snapshot_countdown(console):
    class WindowContract(SessionContract):
        def __init__(self):
            super().__init__()
            self.pending = None
            self.rows[CURSOR]["controller_observation"]["remaining_ms"] = 100

        def route(self, route):
            if urlsplit(route.request.url).path.endswith("/transactions/" + CURSOR):
                self.calls.append((route.request.method, urlsplit(route.request.url).path, None))
                self.pending = route
                return
            return super().route(route)

    page, contract = console(_contract=WindowContract)
    page.locator('[data-defense="history"]').get_by_role("button").filter(has_text=CURSOR).click()
    page.wait_for_timeout(250)
    assert contract.pending is not None
    contract.pending.fulfill(
        content_type="application/json", body=json.dumps(contract.rows[CURSOR])
    )
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    expect(section.get_by_role("button", name="启动这一次防护会话", exact=True)).to_be_disabled()
    expect(section).to_contain_text("原观察窗口已到期")
    assert writes(contract) == [] and not contract.errors
