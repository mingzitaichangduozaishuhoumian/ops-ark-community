"""Strict registered-reference routes, with no transport or environment access."""

import sqlite3

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from opsark.defense_recheck_api import DefenseRecheckRequest, register_defense_recheck_routes
from opsark.defense_store import DefenseConflict

HOST, RID, RUN = "fixture", "a" * 32, "b" * 32
PREFIX = f"/api/hosts/{HOST}/ssh-defense/transactions/{RID}"
BODY = {
    "run_ref": RUN,
    "expected_manifest_sha256": "c" * 64,
    "expected_profile_sha256": "d" * 64,
    "confirm_recheck": True,
}


class StubService:
    def __init__(self):
        self.calls = []
        self.failure = None

    def _call(self, operation, *args, **kwargs):
        self.calls.append((operation, args, kwargs))
        if self.failure is not None:
            raise self.failure
        return {"run_ref": RUN, "current_verdict": "pending"}

    def start(self, *args, **kwargs):
        return self._call("start", *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._call("get", *args, **kwargs)

    def interrupt(self, *args, **kwargs):
        return self._call("interrupt", *args, **kwargs)

    def legacy_get(self, *args, **kwargs):
        return self._call("legacy_get", *args, **kwargs)

    def legacy_list(self, *args, **kwargs):
        return self._call("legacy_list", *args, **kwargs)

    def legacy_handoff(self, *args, **kwargs):
        self._call("legacy_handoff", *args, **kwargs)
        return "# 旧记录\n\n待验收。\n"

    def list(self, *args, **kwargs):
        return self._call("list", *args, **kwargs)

    def handoff(self, *args, **kwargs):
        self._call("handoff", *args, **kwargs)
        return "# 已记录的安全摘要\n\n待验收。\n"


@pytest.fixture
def client():
    allowed = [True]
    service = StubService()

    def protected():
        if not allowed[0]:
            raise HTTPException(401, "Authentication required")

    app = FastAPI()
    register_defense_recheck_routes(app, service, [Depends(protected)])
    return TestClient(app), service, allowed


@pytest.mark.parametrize(
    "verb,path",
    [
        ("get", "/rechecks"),
        ("get", "/rechecks/" + RUN),
        ("post", "/rechecks"),
        ("get", "/handoff"),
        ("post", "/rechecks/" + RUN + "/interrupt"),
        ("get", "/legacy-rechecks"),
        ("get", "/legacy-rechecks/" + RUN),
        ("get", "/legacy-rechecks/" + RUN + "/handoff"),
    ],
)
def test_all_routes_are_protected(client, verb, path):
    browser, service, allowed = client
    allowed[0] = False
    response = (
        browser.post(PREFIX + path, json=BODY) if verb == "post" else browser.get(PREFIX + path)
    )
    assert response.status_code == 401 and service.calls == []


def test_start_accepts_only_the_four_reference_and_confirmation_fields(client):
    browser, service, _ = client
    assert browser.post(PREFIX + "/rechecks", json=BODY).status_code == 200
    operation, args, _ = service.calls[-1]
    assert operation == "start" and args[:2] == (HOST, RID)
    assert type(args[2]) is DefenseRecheckRequest


@pytest.mark.parametrize(
    "change",
    [
        {"confirm_recheck": False},
        {"confirm_recheck": 1},
        {"confirm_recheck": "true"},
        {"run_ref": "bad-reference-canary"},
        {"expected_manifest_sha256": True},
        {"expected_profile_sha256": "bad-profile-canary"},
        {"checks": [{"status": "passed", "raw": "check-secret-canary"}]},
        {"command": "shell-secret-canary"},
        {"url": "https://private-canary.invalid"},
        {"report_id": "unrelated-report-canary"},
        {"approval_id": "e" * 32},
    ],
)
def test_invalid_client_evidence_and_confirmation_are_rejected_without_reflection(client, change):
    browser, service, _ = client
    response = browser.post(PREFIX + "/rechecks", json=BODY | change)
    assert response.status_code == 422 and service.calls == []
    assert "canary" not in response.text and "passed" not in response.text


def test_get_and_pagination_are_local_reference_calls(client):
    browser, service, _ = client
    assert browser.get(PREFIX + "/rechecks/" + RUN).status_code == 200
    assert service.calls[-1] == ("get", (HOST, RID, RUN), {})
    assert browser.get(PREFIX + "/rechecks?after_sequence=9&limit=3").status_code == 200
    assert service.calls[-1] == ("list", (HOST, RID), {"after_sequence": 9, "limit": 3})


@pytest.mark.parametrize("query", ["limit=0", "limit=21", "after_sequence=-1", "limit=true"])
def test_invalid_pagination_never_reaches_the_service(client, query):
    browser, service, _ = client
    assert browser.get(PREFIX + "/rechecks?" + query).status_code == 422
    assert not service.calls


def test_handoff_without_selected_run_does_not_select_latest(client):
    browser, service, _ = client
    response = browser.get(PREFIX + "/handoff")
    assert response.status_code == 200 and "待验收" in response.text
    assert service.calls[-1] == ("handoff", (HOST, RID), {"run_ref": None})
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="opsark-defense-handoff.md"'
    )
    browser.get(PREFIX + "/handoff?run_ref=" + RUN)
    assert service.calls[-1] == ("handoff", (HOST, RID), {"run_ref": RUN})


@pytest.mark.parametrize(
    "failure,status",
    [
        (DefenseConflict("secret-conflict-canary"), 409),
        (sqlite3.OperationalError("secret-db-canary"), 503),
        (OSError("secret-path-canary"), 503),
    ],
)
def test_service_errors_have_fixed_safe_messages(client, failure, status):
    browser, service, _ = client
    service.failure = failure
    response = browser.get(PREFIX + "/rechecks")
    assert response.status_code == status and "canary" not in response.text


def test_explicit_interrupt_is_bound_to_original_declaration(client):
    browser, service, _ = client
    body = {"expected_declaration_sha256": "e" * 64, "confirm_interrupt": True}
    response = browser.post(PREFIX + "/rechecks/" + RUN + "/interrupt", json=body)
    assert response.status_code == 200
    operation, args, _ = service.calls[-1]
    assert operation == "interrupt" and args[:3] == (HOST, RID, RUN)
    assert args[3].expected_declaration_sha256 == "e" * 64


@pytest.mark.parametrize("confirmation", [False, 1, "true", None])
def test_interrupt_confirmation_cannot_be_coerced(client, confirmation):
    browser, service, _ = client
    response = browser.post(
        PREFIX + "/rechecks/" + RUN + "/interrupt",
        json={"expected_declaration_sha256": "e" * 64, "confirm_interrupt": confirmation},
    )
    assert response.status_code == 422 and service.calls == []


def test_legacy_reads_and_exports_have_separate_routes(client):
    browser, service, _ = client
    assert browser.get(PREFIX + "/legacy-rechecks?after_sequence=2&limit=4").status_code == 200
    assert service.calls[-1] == ("legacy_list", (HOST, RID), {"after_sequence": 2, "limit": 4})
    assert browser.get(PREFIX + "/legacy-rechecks/" + RUN).status_code == 200
    assert service.calls[-1] == ("legacy_get", (HOST, RID, RUN), {})
    response = browser.get(PREFIX + "/legacy-rechecks/" + RUN + "/handoff")
    assert response.status_code == 200
    assert service.calls[-1] == ("legacy_handoff", (HOST, RID, RUN), {})
    assert "opsark-defense-legacy-handoff.md" in response.headers["content-disposition"]
