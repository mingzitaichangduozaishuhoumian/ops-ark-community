"""Real Chromium, synthetic local API: follow-up alerts cannot replay actions."""

import json
from urllib.parse import urlsplit

from playwright.sync_api import expect
from test_defense_web import ACTION, TOKEN, Contract, stamp, transaction
from test_defense_web import browser as browser
from test_defense_web import console as console

REF = "7" * 32
PRIVATE = "unclassified-raw-secret-not-a-display-field"


class WatchContract(Contract):
    def __init__(
        self,
        *,
        watch_enabled=True,
        bad_state=False,
        capacity_limited=False,
        discovery_incomplete=False,
    ):
        super().__init__(mode="manual", ai_required=False)
        self.watch_enabled, self.bad_state = watch_enabled, bad_state
        self.capacity_limited = capacity_limited
        self.discovery_incomplete = discovery_incomplete
        self.rows[ACTION] = transaction("action", "active")
        self.acknowledged = None

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if path != "/api/capabilities" and not path.startswith("/api/ssh-defense/task-watch"):
            return super().route(route)
        assert request.headers.get("authorization") == "Bearer " + TOKEN
        body = request.post_data_json if request.post_data else None
        self.calls.append((request.method, path, body))
        row = {
            "event_ref": REF,
            "sequence": 1,
            "task_reference_sha256": "8" * 64,
            "host_id": "synthetic-a",
            "request_id": ACTION,
            "state": PRIVATE if self.bad_state else "unavailable",
            "observed_at": stamp(-2),
            "acknowledged_at": self.acknowledged,
            "raw_log": PRIVATE,
        }
        if path == "/api/capabilities":
            value = {
                "mode": "read_only",
                "automation_modes": True,
                "ssh_defense_transactions": True,
                "ssh_defense_task_watch": True,
                "security_observation": False,
            }
        elif path == "/api/ssh-defense/task-watch":
            value = {
                "v": 1,
                "enabled": self.watch_enabled,
                "running": self.watch_enabled,
                "host_ids": ["synthetic-a"],
                "interval_seconds": 60,
                "continuous_execution": False,
                "reason_code": "capacity_limit"
                if self.capacity_limited
                else "running"
                if self.watch_enabled
                else "disabled",
                "capacity_limited": self.capacity_limited,
                "discovery_incomplete": self.discovery_incomplete,
                "counts": {
                    "tasks": 1,
                    "pending": 1,
                    "alerts": 1,
                    "unread": 0 if self.acknowledged else 1,
                },
            }
        elif path == "/api/ssh-defense/task-watch/events":
            value = {"v": 1, "events": [row], "next_after_sequence": None}
        else:
            assert path == "/api/ssh-defense/task-watch/events/" + REF + "/ack"
            assert request.method == "POST" and body == {"confirm_ack": True}
            self.acknowledged = stamp()
            row["acknowledged_at"] = self.acknowledged
            value = row
        route.fulfill(content_type="application/json", body=json.dumps(value))


def test_watch_alert_ack_and_open_keep_same_task_without_execution(console):
    page, contract = console(_contract=WatchContract)
    page.set_viewport_size({"width": 390, "height": 844})
    section = page.get_by_role("region", name="原任务只读跟进", exact=True)
    expect(section.get_by_text("未取得可信查询回执", exact=True)).to_be_visible()
    assert PRIVATE not in page.locator("body").inner_text()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    section.get_by_role("button", name="仅标记已阅", exact=True).click()
    expect(section.get_by_role("button", name="仅标记已阅", exact=True)).to_have_count(0)
    expect(
        page.get_by_text("仅标记告警已阅；原任务、执行暂停、配额和授权保持。", exact=True)
    ).to_be_visible()
    section.get_by_role("button", name="打开对应原任务", exact=True).click()
    expect(page.locator('[data-defense="detail"]')).to_contain_text(ACTION)
    writes = [call for call in contract.calls if call[0] not in {"GET", "HEAD"}]
    assert writes == [
        ("POST", "/api/ssh-defense/task-watch/events/" + REF + "/ack", {"confirm_ack": True})
    ]
    assert not contract.errors


def test_disabled_followup_is_deployment_owned_and_history_only(console):
    page, contract = console(_contract=WatchContract, watch_enabled=False)
    section = page.get_by_role("region", name="原任务只读跟进", exact=True)
    expect(section).to_contain_text("部署未启用；已有告警仅供核对")
    expect(section).to_contain_text("持续自动执行")
    assert section.get_by_role("button", name="开启", exact=True).count() == 0
    assert all(method in {"GET", "HEAD"} for method, _, _ in contract.calls)
    assert not contract.errors


def test_unknown_followup_state_is_not_rendered_as_upstream_text(console):
    page, contract = console(_contract=WatchContract, bad_state=True)
    section = page.get_by_role("region", name="原任务只读跟进", exact=True)
    expect(section).to_contain_text("跟进记录暂未核实")
    assert PRIVATE not in page.locator("body").inner_text()
    assert section.get_by_role("button", name="打开对应原任务", exact=True).count() == 0
    assert not contract.errors


def test_acknowledging_alert_does_not_clear_followup_capacity_limit(console):
    page, contract = console(
        _contract=WatchContract, capacity_limited=True, discovery_incomplete=True
    )
    section = page.get_by_role("region", name="原任务只读跟进", exact=True)
    expect(section).to_contain_text("新增跟进已暂停")
    expect(section).to_contain_text("历史仍在分批登记；暂无事件不代表已完成跟进")
    section.get_by_role("button", name="仅标记已阅", exact=True).click()
    expect(section.get_by_role("button", name="仅标记已阅", exact=True)).to_have_count(0)
    expect(section).to_contain_text("标为已阅不解除容量限制或执行门禁")
    assert contract.capacity_limited and not contract.errors
