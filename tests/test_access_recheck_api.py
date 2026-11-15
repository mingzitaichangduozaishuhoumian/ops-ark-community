"""An SSH outage report accepts only fresh, bound, bodyless rechecks."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from opsark import collector, main
from opsark.business_readiness import BusinessCheckResult, BusinessReadiness
from opsark.config import HostConfig, Settings
from opsark.models import BusinessCheck, CheckResult, Collection, HostPublic
from opsark.replay import collect_replay

TOKEN = "synthetic-access-recheck-test-token-1111"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
HOST = "access-fixture"
INVESTIGATE = {"source": "ssh", "scenario": "web_502", "host_id": HOST}


def test_outage_rechecks_keep_the_original_and_history(tmp_path, monkeypatch):
    registered = HostConfig(
        HostPublic(
            id=HOST,
            name="synthetic",
            address="192.0.2.1",
            source="ssh",
            trusted_hosts_digest="a" * 64,
        ),
        tmp_path / "key-fixture",
        tmp_path / "host-fixture",
        compose_project="synthetic",
        container_binding_confirmed=False,
        business_checks=(
            BusinessCheck(
                id="primary",
                domain="site.invalid",
                path="/ready",
                expected_body_sha256="b" * 64,
                read_only_confirmed=True,
            ),
        ),
    )
    hosts = {HOST: registered}
    monkeypatch.setattr(main, "load_hosts", lambda _: hosts)
    up = True

    def investigate(host, _scenario):
        if up:
            return collect_replay("web-port-mismatch")[1].model_copy(
                update={"host_id": HOST, "source": "ssh"}
            )
        return Collection(
            host_id=HOST,
            source="ssh",
            started_at=datetime.now(UTC),
            duration_ms=1,
            checks=[
                CheckResult(
                    name="connection",
                    status="error",
                    exit_code=None,
                    stderr="synthetic-confidential-collector-marker",
                )
            ],
        )

    mode = "unavailable"
    calls = []

    def collect(host):
        calls.append(host.public.id)
        return mode != "unavailable", BusinessReadiness(
            host_id=HOST,
            status="inconclusive" if mode == "unavailable" else mode,
            checks=[
                BusinessCheckResult(
                    id="primary",
                    status="inconclusive" if mode == "unavailable" else mode,
                    http_status=None if mode == "unavailable" else 200,
                )
            ],
        )

    monkeypatch.setattr(main, "collect_ssh", investigate)
    monkeypatch.setattr(main, "run_access_readiness", collect)
    settings = Settings(tmp_path, TOKEN)
    with TestClient(main.create_app(settings)) as client:
        healthy = client.post("/api/investigations", headers=AUTH, json=INVESTIGATE).json()
        assert (
            client.post(
                f"/api/reports/{healthy['id']}/baseline",
                headers=AUTH,
                json={"confirm_observation_only": True},
            ).status_code
            == 200
        )
        up = False
        report = client.post("/api/investigations", headers=AUTH, json=INVESTIGATE).json()
        root = f"/api/reports/{report['id']}"
        endpoint = root + "/access-rechecks"
        assert client.get(endpoint).status_code == 401
        assert (
            client.post(endpoint, headers=AUTH, json={"url": "https://site.invalid/"}).status_code
            == 422
        )
        history = client.get(endpoint, headers=AUTH).json()
        assert history["can_run"] and history["last_evidence_at"] and history["rechecks"] == []
        assert (
            client.post(
                root + "/baseline",
                headers=AUTH,
                json={
                    "confirm_observation_only": True,
                },
            ).status_code
            == 409
        )
        rows = []
        for business_mode, external, status in (
            ("unavailable", "matched", "pending"),
            ("unavailable", "unreachable", "failed"),
            ("passed", "unavailable", "pending"),
            ("failed", "matched", "failed"),
            ("passed", "matched", "accepted"),
        ):
            mode = business_mode
            reply = client.post(endpoint, headers=AUTH, json={"external": external})
            assert reply.status_code == 201 and reply.headers["cache-control"] == "no-store"
            row = reply.json()
            assert row["status"] == status and row["report_id"] == report["id"]
            rows.append(row)
        assert len(calls) == 5
        assert client.get(root, headers=AUTH).json() == report
        hosts[HOST] = replace(
            registered,
            business_checks=(
                registered.business_checks[0].model_copy(update={"path": "/changed"}),
            ),
        )
        assert client.post(endpoint, headers=AUTH, json={}).status_code == 409
        assert len(calls) == 5

    with TestClient(main.create_app(settings)) as client:
        history = client.get(endpoint, headers=AUTH).json()
        assert not history["can_run"] and history["rechecks"] == list(reversed(rows))
        for row, phrase in zip(
            rows[:2] + rows[-1:], ("待验收", "复验未通过", "复验通过"), strict=True
        ):
            exported = client.get(endpoint + f"/{row['id']}/handoff", headers=AUTH)
            assert exported.status_code == 200 and phrase in exported.text
            assert "机外观察（人工记录）" in exported.text
            for private in ("site.invalid", "192.0.2.1", "synthetic-confidential-collector-marker"):
                assert private not in exported.text


@pytest.mark.parametrize("scenario", ["web_502", "container_restart"])
def test_unconfirmed_container_keeps_real_connection_failure(monkeypatch, tmp_path, scenario):
    target = HostConfig(
        HostPublic(id=HOST, name="synthetic", address="192.0.2.1", source="ssh"),
        tmp_path / "key-fixture",
        tmp_path / "host-fixture",
        container_binding_confirmed=False,
    )
    unavailable = Collection(
        host_id=HOST,
        source="ssh",
        started_at=datetime.now(UTC),
        checks=[CheckResult(name="connection", status="error", exit_code=None)],
    )
    monkeypatch.setattr(collector, "_collect", lambda *_: unavailable)
    assert [check.name for check in collector.collect_ssh(target, scenario).checks] == [
        "connection"
    ]
