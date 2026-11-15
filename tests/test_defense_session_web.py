"""Real Chromium with local synthetic contracts for explicit one-window sessions."""

import json
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect
from test_defense_web import ACTION, CURSOR, TOKEN, Contract, confirm, stamp, transaction
from test_defense_web import browser as browser
from test_defense_web import console as console

PRIVATE = "FAKE_RAW_SOURCE_PRIVATE_TEXT"
REF = "f" * 32


def record(ref, phase="observing", *, owned=True):
    return {
        "v": 1,
        "sequence": 1,
        "host_id": "synthetic-a",
        "session_ref": ref,
        "cursor_request_id": CURSOR,
        "action_request_id": ACTION if phase != "observing" else None,
        "declaration_sha256": "9" * 64,
        "phase": phase,
        "effective_phase": phase,
        "created_at": stamp(-2),
        "updated_at": stamp(),
        "controller_deadline_at": stamp(90),
        "mode_revision": 3,
        "requires_ai": True,
        "max_actions_per_session": 1,
        "max_ai_intents": 1,
        "business_verdict": "pending",
        "stop_reason": None,
        "owned_by_current_boot": owned,
        "can_stop": owned and phase not in ("stopped", "expired", "reconciliation_only"),
        "source": PRIVATE,
    }


class SessionContract(Contract):
    def __init__(self, *, enabled=True, manual=False, lost=False, history=False, attached=False):
        super().__init__(mode="manual" if manual else "automatic", ai_required=False)
        self.sender_enabled, self.lost = enabled, lost
        self.session_rows = (
            {REF: record(REF, "reconciliation_only", owned=False)} if history else {}
        )
        self.rows[CURSOR] = transaction("cursor", "attached" if attached else "armed")
        self.rows[CURSOR]["controller_observation"] = {
            "owned_by_current_boot": True,
            "deadline_at": stamp(110),
            "remaining_ms": 110000,
        }
        self.rows[ACTION] = transaction("action", "active")

    def route(self, route):
        req = route.request
        path = urlsplit(req.url).path
        base = "/api/hosts/synthetic-a/ssh-defense/sessions"
        if (
            path != "/api/capabilities"
            and path != "/api/ssh-defense/sessions/status"
            and not path.startswith(base)
        ):
            return super().route(route)
        assert req.headers.get("authorization") == "Bearer " + TOKEN
        body = req.post_data_json if req.post_data else None
        self.calls.append((req.method, path, body))
        if path == "/api/capabilities":
            value = {
                "mode": "read_only",
                "automation_modes": True,
                "ssh_defense_transactions": True,
                "ssh_defense_sessions": True,
                "security_observation": False,
            }
        elif path == "/api/ssh-defense/sessions/status":
            value = {
                "v": 1,
                "enabled": self.sender_enabled,
                "running": self.sender_enabled,
                "session_only": True,
                "continuous_execution": False,
                "max_actions_per_session": 1,
                "mutation_owner": True,
                "owned_sessions": len(self.session_rows),
            }
        elif path == base and req.method == "POST":
            assert body is not None
            assert body["cursor_request_id"] == CURSOR and body["expected_mode_revision"] == 3
            assert body["confirm_session"] is True and len(body["session_ref"]) == 32
            value = record(body["session_ref"])
            self.session_rows[value["session_ref"]] = value
            if self.lost:
                route.abort("connectionreset")
                return
        elif path == base:
            value = {
                "v": 1,
                "host_id": "synthetic-a",
                "sessions": list(self.session_rows.values()),
                "next_after_sequence": None,
            }
        elif path.endswith("/stop"):
            ref = path.split("/")[-2]
            assert body == {"expected_declaration_sha256": "9" * 64, "confirm_stop": True}
            value = self.session_rows[ref] = record(ref, "stopped")
        else:
            value = self.session_rows[path.rsplit("/", 1)[-1]]
        route.fulfill(content_type="application/json", body=json.dumps(value))


def select_cursor(page):
    page.locator('[data-defense="history"]').get_by_role("button").filter(has_text=CURSOR).click()


@pytest.mark.parametrize("width", [320, 390, 768, 1440])
def test_explicit_session_start_stop_and_pending_business_fit_four_viewports(console, width):
    page, contract = console(_contract=SessionContract)
    page.set_viewport_size({"width": width, "height": 900})
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text(CURSOR)
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text("最多一次动作")
    confirm(page)
    expect(section).to_contain_text("待验收 · 未进行独立业务复验")
    assert PRIVATE not in page.locator("body").inner_text()
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    section.get_by_role("button", name="核对并停止原会话", exact=True).click()
    expect(page.locator('[data-defense="dialog-summary"]')).to_contain_text("9" * 64)
    confirm(page)
    expect(section).to_contain_text("会话已停止")
    writes = [r for r in contract.calls if r[0] not in ("GET", "HEAD")]
    assert (
        len(writes) == 2 and writes[0][1].endswith("/sessions") and writes[1][1].endswith("/stop")
    )


def test_unknown_start_only_queries_original_ref_without_reposting(console):
    page, contract = console(_contract=SessionContract, lost=True)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    confirm(page)
    expect(
        page.get_by_text("未确认会话回执，只读取这个原会话标识；不会自动重试提交。", exact=True)
    ).to_be_visible()
    posted = [r for r in contract.calls if r[0] == "POST"]
    assert len(posted) == 1
    ref = posted[0][2]["session_ref"]
    section.get_by_role("button", name="只查询未确认的原会话", exact=True).click()
    expect(section).to_contain_text("待验收 · 未进行独立业务复验")
    assert len([r for r in contract.calls if r[0] == "POST"]) == 1
    assert any(r[0] == "GET" and r[1].endswith("/sessions/" + ref) for r in contract.calls)


class MultiHostSessionContract(SessionContract):
    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        base = "/api/hosts/synthetic-b/ssh-defense/sessions"
        if path.startswith(base):
            assert request.headers.get("authorization") == "Bearer " + TOKEN
            body = request.post_data_json if request.post_data else None
            self.calls.append((request.method, path, body))
            if path == base and request.method == "GET":
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
            else:
                route.fulfill(
                    status=404, content_type="application/json", body='{"detail":"Missing"}'
                )
            return
        return super().route(route)


def test_unknown_original_host_and_ref_survive_host_switch_without_wrong_get_or_repost(console):
    page, contract = console(_contract=MultiHostSessionContract, lost=True)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    confirm(page)
    pending = section.get_by_role("button", name="只查询未确认的原会话", exact=True)
    expect(pending).to_be_visible()
    posted = [call for call in contract.calls if call[0] == "POST"]
    assert len(posted) == 1
    reference = posted[0][2]["session_ref"]
    page.locator('[data-defense="host"]').select_option("synthetic-b")
    expect(pending).to_have_count(0)
    expect(section).not_to_contain_text(reference)
    assert not any(
        call[1].startswith("/api/hosts/synthetic-b/ssh-defense/sessions/")
        for call in contract.calls
    )
    page.locator('[data-defense="host"]').select_option("synthetic-a")
    expect(pending).to_be_visible()
    pending.click()
    expect(section).to_contain_text("待验收 · 未进行独立业务复验")
    assert any(
        call[0] == "GET" and call[1] == "/api/hosts/synthetic-a/ssh-defense/sessions/" + reference
        for call in contract.calls
    )
    assert not any(
        call[1].startswith("/api/hosts/synthetic-b/ssh-defense/sessions/")
        for call in contract.calls
    )
    assert len([call for call in contract.calls if call[0] == "POST"]) == 1


def test_candidate_already_attached_still_uses_the_same_explicit_cursor(console):
    page, contract = console(_contract=SessionContract, attached=True)
    select_cursor(page)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    confirm(page)
    posted = [r for r in contract.calls if r[0] == "POST"]
    assert len(posted) == 1 and posted[0][2]["cursor_request_id"] == CURSOR


def test_manual_disabled_instance_opens_history_and_readonly_original_task(console):
    page, contract = console(_contract=SessionContract, enabled=False, manual=True, history=True)
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    expect(section).to_contain_text("此实例未由部署端启用单次会话；历史仍可读取。")
    expect(section.get_by_role("button", name="启动这一次防护会话", exact=True)).to_be_disabled()
    section.get_by_role("button").filter(has_text="只读对账 · 待验收").click()
    expect(section.get_by_role("button", name="核对并停止原会话", exact=True)).to_have_count(0)
    section.get_by_role("button", name="只读核对原任务", exact=True).click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text(ACTION)
    writes = [r for r in contract.calls if r[0] not in ("GET", "HEAD")]
    assert writes == [
        ("POST", "/api/hosts/synthetic-a/ssh-defense/transactions/" + ACTION + "/query", {})
    ]
    assert PRIVATE not in page.locator("body").inner_text()
