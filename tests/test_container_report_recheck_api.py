"""Verify read-only snapshots remain bound to a container report and its registration."""

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from opsark import main
from opsark.business_readiness import BusinessCheckResult, BusinessReadiness
from opsark.config import HostConfig, Settings
from opsark.models import BusinessCheck, HostPublic, Report
from opsark.replay import collect_replay
from opsark.storage import ReportStore

HOST = "container-recheck-fixture"
TOKEN = "synthetic-container-report-test-token"
AUTH = {"Authorization": "Bearer " + TOKEN}
INVESTIGATE = {"source": "ssh", "scenario": "container_restart", "host_id": HOST}
MARKER = "synthetic-original-log-should-stay-private"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    host = HostConfig(
        HostPublic(
            id=HOST,
            name="Synthetic test host",
            address="192.0.2.14",
            source="ssh",
            trusted_hosts_digest="a" * 64,
        ),
        tmp_path / "synthetic-key-reference",
        tmp_path / "synthetic-trust-reference",
        business_checks=tuple(
            BusinessCheck(
                id=identifier,
                domain="private.invalid",
                path="/private-readiness",
                expected_body_sha256=str(number) * 64,
                read_only_confirmed=True,
            )
            for number, identifier in enumerate(
                ("private_primary", "private_shared", "private_control"), 1
            )
        ),
    )
    hosts = {HOST: host}
    monkeypatch.setattr(main, "load_hosts", lambda _: hosts.copy())

    def collect_ssh(_host, _scenario):
        _, replay = collect_replay("container-oom")
        results = [
            check.model_copy(update={"stdout": MARKER}) if check.name == "container_logs" else check
            for check in replay.checks
        ]
        return replay.model_copy(update={"host_id": HOST, "source": "ssh", "checks": results})

    monkeypatch.setattr(main, "collect_ssh", collect_ssh)
    return Settings(tmp_path, TOKEN), hosts, host


def registration_changed(host):
    return replace(
        host,
        business_checks=(
            host.business_checks[0].model_copy(update={"path": "/different"}),
            *host.business_checks[1:],
        ),
    )


def investigation(client):
    assert client.get("/api/capabilities", headers=AUTH).json()["container_report_rechecks"] is True
    response = client.post("/api/investigations", json=INVESTIGATE, headers=AUTH)
    assert response.status_code == 200
    return response.json()


def request(client, path, index):
    return client.post(path, json={"request_id": f"{index:032x}"}, headers=AUTH)


def test_mixed_and_recovered_results_attach_to_same_immutable_investigation(
    environment, monkeypatch
):
    settings, hosts, host = environment
    outcomes = iter(
        (
            (True, ("failed", "inconclusive", "passed")),
            (True, ("passed", "inconclusive", "passed")),
            (True, ("passed", "passed", "passed")),
            (False, ("inconclusive", "inconclusive", "inconclusive")),
        )
    )
    probes = []

    def collect(current):
        probes.append(current)
        authenticated, checks = next(outcomes)
        return authenticated, BusinessReadiness(
            host_id=HOST,
            status="inconclusive",
            checks=[
                BusinessCheckResult(id=item.id, status=value)
                for item, value in zip(current.business_checks, checks, strict=True)
            ],
        )

    monkeypatch.setattr(main, "run_access_readiness", collect)
    monkeypatch.setattr(main, "explain", lambda *_args: pytest.fail("unexpected model call"))
    rows, exports = [], []
    with TestClient(main.create_app(settings)) as client:
        original = investigation(client)
        root = "/api/reports/" + original["id"]
        endpoint = root + "/container-rechecks"
        original_docs = {
            url: client.get(url, headers=AUTH).content for url in (root, root + "/handoff")
        }
        assert client.get(endpoint).status_code == 401
        assert client.get(endpoint, headers=AUTH).json() == {
            "report_id": original["id"],
            "can_run": True,
            "rechecks": [],
        }
        assert (
            client.post(
                endpoint, headers=AUTH, json={"request_id": "a" * 32, "path": "/other"}
            ).status_code
            == 422
        )
        for index, (status, label) in enumerate(
            (
                ("failed", "复验未通过"),
                ("pending", "待验收"),
                ("passed", "复验通过"),
                ("pending", "待验收"),
            ),
            1,
        ):
            reply = request(client, endpoint, index)
            assert reply.status_code == 201 and reply.headers["cache-control"] == "no-store"
            row = reply.json()
            assert set(row) == {"id", "report_id", "finished_at", "management", "checks", "status"}
            assert row["status"] == status and row["report_id"] == original["id"]
            assert request(client, endpoint, index).json() == row
            url = endpoint + f"/{row['id']}/handoff"
            assert client.get(url).status_code == 401
            export = client.get(url, headers=AUTH)
            assert export.status_code == 200 and label in export.text
            assert all(
                private not in export.text
                for private in (
                    MARKER,
                    TOKEN,
                    "192.0.2.14",
                    "private.invalid",
                    "/private-readiness",
                    "private_primary",
                )
            )
            rows.append(row)
            exports.append((url, export.content))
        assert probes == [host] * 4
        assert all(
            client.get(url, headers=AUTH).content == content
            for url, content in original_docs.items()
        )
        other = "/api/reports/" + investigation(client)["id"] + "/container-rechecks"
        assert client.get(other + f"/{rows[0]['id']}/handoff", headers=AUTH).status_code == 404
        hosts[HOST] = registration_changed(host)
        assert request(client, endpoint, 99).status_code == 409
        previous = request(client, endpoint, 1)
        assert previous.status_code == 201 and previous.json() == rows[0]

    with TestClient(main.create_app(settings)) as client:
        assert client.get(endpoint, headers=AUTH).json() == {
            "report_id": original["id"],
            "can_run": False,
            "rechecks": list(reversed(rows)),
        }
        assert all(client.get(url, headers=AUTH).content == content for url, content in exports)
    assert probes == [host] * 4


def test_range_change_during_collection_refuses_partial_receipt_and_old_reports_stay_readable(
    environment,
    monkeypatch,
):
    settings, hosts, host = environment

    def collect(current):
        hosts[HOST] = registration_changed(current)
        return True, BusinessReadiness(
            host_id=HOST,
            status="passed",
            checks=[
                BusinessCheckResult(id=check.id, status="passed")
                for check in current.business_checks
            ],
        )

    monkeypatch.setattr(main, "run_access_readiness", collect)
    with TestClient(main.create_app(settings)) as client:
        original = investigation(client)
        endpoint = "/api/reports/" + original["id"] + "/container-rechecks"
        assert request(client, endpoint, 1).status_code == 409
        assert client.get(endpoint, headers=AUTH).json()["rechecks"] == []
        hosts[HOST] = host
        legacy = Report.model_validate_json(
            client.get(endpoint.removesuffix("/container-rechecks"), headers=AUTH).content
        )
        legacy.id = "legacy-container-report"
        ReportStore(settings.data_dir / "reports.sqlite3").save(legacy)
        old = "/api/reports/legacy-container-report/container-rechecks"
        assert client.get(old, headers=AUTH).json() == {
            "report_id": legacy.id,
            "can_run": False,
            "rechecks": [],
        }
        assert request(client, old, 2).status_code == 409
