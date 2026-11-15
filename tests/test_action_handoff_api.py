"""Exercise structured action customer export and bodyless verification through HTTP."""

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from test_action_handoff_projection import container as container
from test_action_handoff_projection import container_product as container_product
from test_action_handoff_projection import nginx as nginx
from test_action_handoff_projection import nginx_product as nginx_product
from test_container_restarts import approve as approve_container

from opsark.action_handoff_api import register_action_handoff_routes
from opsark.action_handoff_projection import ActionHandoffProjection
from opsark.action_handoff_recheck_store import ActionHandoffRecheckStore
from opsark.business_readiness import BusinessCheckResult, BusinessReadiness


def route_client(state, profile, status, *, drift=False):
    from threading import Lock

    app = FastAPI()
    records = ActionHandoffRecheckStore(state.store)
    projection = ActionHandoffProjection(
        state.store, state.nginx_action_service, state.container_restart_service, records
    )
    hosts = {profile.public.id: profile}
    calls = []

    def report_or_404(report_id):
        report = state.store.get(report_id)
        if report is None:
            raise HTTPException(404)
        return report

    def collect(target):
        calls.append(target.public.id)
        if drift:
            hosts.clear()
        return BusinessReadiness(
            host_id=target.public.id,
            status=status.value,
            checks=[BusinessCheckResult(id=target.business_checks[0].id, status=status.value)],
        )

    def authenticate(authorization: str | None = Header(default=None)):
        if authorization != "Bearer synthetic-action-handoff":
            raise HTTPException(401)

    def current_hosts():
        if getattr(status, "inventory_unavailable", False):
            raise OSError("synthetic unreadable inventory")
        return hosts

    register_action_handoff_routes(
        app.router,
        projection,
        records,
        [Depends(authenticate)],
        nginx=state.nginx_action_service,
        container=state.container_restart_service,
        find_report=report_or_404,
        registered_hosts=dict(hosts),
        current_hosts=current_hosts,
        collect=collect,
        collection_lock=Lock(),
    )
    return app, hosts, calls


@pytest.mark.parametrize("kind", ["container_restart", "nginx"])
def test_action_handoff_download_has_no_raw_evidence_and_get_never_collects(request, kind):
    if kind == "container_restart":
        product, transport, profile, report, action = request.getfixturevalue("container")
        transport.status = "verified"
        assert approve_container(product, action).json()["status"] == "verified"
    else:
        product, _transport, profile, report, _, action = request.getfixturevalue("nginx")
    url = f"/api/reports/{report.id}/handoff-actions/{kind}/{action['plan_id']}"
    status = SimpleNamespace(value="inconclusive")
    app, hosts, calls = route_client(product.app.state, profile, status)
    with TestClient(app, headers={"Authorization": "Bearer synthetic-action-handoff"}) as client:
        assert client.get(url, headers={"Authorization": "Bearer invalid"}).status_code == 401
        assert (
            client.post(url + "/rechecks", headers={"Authorization": "Bearer invalid"}).status_code
            == 401
        )
        listed = client.get(f"/api/reports/{report.id}/handoff-actions")
        assert listed.status_code == 200
        (option,) = listed.json()["actions"]
        assert set(option) == {"kind", "action", "plan_id", "approved_at"}
        assert option["kind"] == kind and option["plan_id"] == action["plan_id"]
        pending = client.get(url)
        assert pending.status_code == 200 and "待验收" in pending.text
        assert client.get(url + "/rechecks").json() == {"can_run": True, "rechecks": []}
        assert calls == []
        timed_out = client.post(url + "/rechecks")
        assert timed_out.status_code == 201 and timed_out.json()["verdict"] == "pending"
        status.value = "failed"
        failed = client.post(url + "/rechecks").json()
        assert failed["verdict"] == "failed"
        status.value = "passed"
        passed = client.post(url + "/rechecks").json()
        assert passed["verdict"] == "passed"
        current = client.get(url)
        assert current.status_code == 200 and "登记业务复验通过" in current.text
        assert current.headers["content-disposition"].endswith('"opsark-action-handoff.md"')
        old = client.get(url, params={"recheck_id": failed["id"]})
        assert old.status_code == 200 and "复验未通过" in old.text
        history = client.get(url + "/rechecks").json()
        assert [row["id"] for row in history["rechecks"]] == [
            passed["id"],
            failed["id"],
            timed_out.json()["id"],
        ]
        assert len(calls) == 3
        assert all(
            value not in current.text + old.text
            for value in (
                report.id,
                action["plan_id"],
                passed["id"],
                "private_probe",
                "private-probe.invalid",
                "/private-probe-canary",
                profile.public.address,
            )
        )
        status.inventory_unavailable = True
        assert client.get(url + "/rechecks").json()["can_run"] is False
        assert "待验收" in client.get(url).text
        assert "复验未通过" in client.get(url, params={"recheck_id": failed["id"]}).text
        status.inventory_unavailable = False
        hosts.clear()
        assert client.get(url + "/rechecks").json()["can_run"] is False
        assert "待验收" in client.get(url).text
        assert "复验未通过" in client.get(url, params={"recheck_id": failed["id"]}).text
        assert client.post(url + "/rechecks").status_code == 409
        assert len(calls) == 3


def test_scope_change_during_explicit_collection_leaves_an_unfinished_attempt(container):
    product, transport, profile, report, action = container
    transport.status = "verified"
    assert approve_container(product, action).json()["status"] == "verified"
    url = f"/api/reports/{report.id}/handoff-actions/container_restart/{action['plan_id']}"
    app, _, calls = route_client(
        product.app.state, profile, SimpleNamespace(value="passed"), drift=True
    )
    with TestClient(app, headers={"Authorization": "Bearer synthetic-action-handoff"}) as client:
        assert client.post(url + "/rechecks").status_code == 409
        assert len(calls) == 1
        history = client.get(url + "/rechecks").json()
        assert history["can_run"] is False
        assert len(history["rechecks"]) == 1 and history["rechecks"][0]["verdict"] == "pending"
        assert "待验收" in client.get(url).text
