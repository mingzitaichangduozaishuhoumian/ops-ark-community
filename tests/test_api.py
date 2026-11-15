import base64
import hashlib
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from opsark import host_preflight, main
from opsark.business_readiness import BusinessCheckResult, BusinessReadiness
from opsark.config import HostConfig, Settings
from opsark.models import (
    AIExplanation,
    BaselineChange,
    BaselineComparison,
    BusinessCheck,
    CheckResult,
    Collection,
    Evidence,
    Finding,
    HealthCheck,
    HostPublic,
    Report,
    Verification,
)

TOKEN = "test-console-token-not-a-real-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SAMPLE = {"id": "api-sample", "title": "测试回放", "scenario": "web_502", "host_id": "demo"}
REQUEST = {"source": "replay", "scenario": "web_502", "sample_id": "api-sample"}


def replay_fixture(sample_id: str) -> tuple[HostPublic, Collection]:
    if sample_id != SAMPLE["id"]:
        raise KeyError(sample_id)
    return HostPublic(id="demo", name="演示", address="192.0.2.10"), Collection(
        host_id="demo",
        source="replay",
        started_at=datetime.now(UTC),
        checks=[
            CheckResult(
                name="nginx_errors",
                stdout="connection refused\nAuthorization: Bearer fixture-private-marker",
            )
        ],
    )


def fake_diagnose(scenario: str, host: HostPublic, collection: Collection) -> Report:
    evidence = [
        Evidence(
            id="e1",
            check_id=collection.checks[0].name,
            target=host.id,
            source=collection.source,
            collected_at=collection.started_at,
            status=collection.checks[0].status,
            output=collection.checks[0].stdout,
        )
    ]
    return Report(
        id="report-1",
        host_id=host.id,
        host_name=host.name,
        scenario=scenario,
        source=collection.source,
        created_at=collection.started_at,
        status="needs_attention" if collection.checks[0].status == "ok" else "inconclusive",
        title="测试调查",
        summary="只读调查，尚未验收恢复。",
        facts=[Finding(text="检查结果。", evidence_ids=["e1"])],
        candidates=[],
        missing=["没有已验收配置。"],
        evidence=evidence,
        next_steps=["补齐证据。"],
    )


def settings_for(path: Path, **overrides: object) -> Settings:
    values = {
        "data_dir": path,
        "token": TOKEN,
        "inventory_path": None,
        "ai_base_url": None,
        "ai_key": None,
        "ai_model": None,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(main, "load_hosts", lambda settings: {})
    monkeypatch.setattr(main, "list_samples", lambda: [dict(SAMPLE)])
    monkeypatch.setattr(main, "collect_replay", replay_fixture)
    monkeypatch.setattr(main, "diagnose", fake_diagnose)
    settings = settings_for(tmp_path)
    application = main.create_app(settings)
    with TestClient(application) as client:
        yield client, application, settings


def test_only_minimal_status_is_public(configured) -> None:
    client, _, _ = configured
    status = client.get("/api/status")
    assert status.status_code == 200
    assert set(status.json()) == {"version", "requires_auth"}
    assert status.json()["requires_auth"] is True
    for endpoint in ["hosts", "samples", "capabilities", "reports"]:
        response = client.get(f"/api/{endpoint}")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert (
            client.get(f"/api/{endpoint}", headers={"Authorization": "Bearer wrong"}).status_code
            == 401
        )
    assert client.get("/api/hosts?token=not-a-real-token", headers=AUTH).status_code == 400
    assert client.get("/api/hosts", headers=AUTH).status_code == 200


def test_onboarding_prepares_verified_config_then_uses_loaded_preflight(tmp_path, monkeypatch):
    key = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    )
    _, public_blob = key.split()
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(public_blob)).digest()
    ).decode().rstrip("=")
    payload = {
        "host_id": "fresh-lab",
        "name": "隔离验证",
        "address": "192.0.2.29",
        "port": 2222,
        "username": "opsark-readonly",
        "site_domain": "lab.invalid",
        "container_name": "api",
        "expected_upstream_port": 8081,
        "host_key": key.decode(),
        "expected_fingerprint": fingerprint,
    }
    endpoint = "/api/host-onboarding/prepare"
    inventory_path = tmp_path / "inventory.toml"
    settings = settings_for(tmp_path / "data")
    preflight_path = "/api/hosts/fresh-lab/preflight"
    reached = []

    def collect(registered):
        reached.append(registered)
        return Collection(
            host_id=registered.public.id,
            source="ssh",
            started_at=datetime.now(UTC),
            checks=[CheckResult(name="connection", status="permission_denied")],
        )

    monkeypatch.setattr(host_preflight, "collect_ssh_preflight", collect)
    with TestClient(main.create_app(settings)) as client:
        assert client.get("/api/capabilities", headers=AUTH).json()["host_onboarding"] is True
        assert client.post(endpoint, json=payload).status_code == 401
        assert (
            client.post(
                endpoint, headers={**AUTH, "Origin": "https://elsewhere.invalid"}, json=payload
            ).status_code
            == 403
        )
        bad = client.post(endpoint, headers=AUTH, json={**payload, "host_key": "PRIVATE-MARKER"})
        assert bad.status_code == 422 and "PRIVATE-MARKER" not in bad.text
        assert (
            client.post(
                endpoint, headers=AUTH, json={**payload, "private_key": "secret"}
            ).status_code
            == 422
        )
        response = client.post(endpoint, headers=AUTH, json=payload)
        assert response.status_code == 200
        result = response.json()
        assert result["fingerprint"] == fingerprint
        assert result["known_hosts"].strip() == "[192.0.2.29]:2222 " + key.decode()
        assert client.post(preflight_path, headers=AUTH, json={}).status_code == 404
        assert not inventory_path.exists() and not reached

    inventory_path.write_text(result["inventory"], encoding="utf-8")
    key_path = tmp_path / result["key_file"]
    key_path.parent.mkdir()
    key_path.write_text("local test placeholder", encoding="utf-8")
    (tmp_path / result["known_hosts_file"]).write_bytes(result["known_hosts"].encode())
    with TestClient(
        main.create_app(settings_for(tmp_path / "data", inventory_path=inventory_path))
    ) as client:
        hosts = client.get("/api/hosts", headers=AUTH).json()
        host = next(host for host in hosts if host["id"] == "fresh-lab")
        assert host["trusted_hosts_digest"] in result["known_hosts_digests"].values()
        response = client.post(preflight_path, headers=AUTH, json={})
        assert response.status_code == 200 and response.json()["connection"] == "permission_denied"
        assert len(reached) == 1 and reached[0].public.port == 2222


def test_host_preflight_is_registered_only_authenticated_and_read_only(tmp_path, monkeypatch):
    host = HostConfig(
        public=HostPublic(id="lab", name="登记主机", address="192.0.2.50", source="ssh"),
        key_file=tmp_path / "private-key-canary",
        known_hosts_file=tmp_path / "trusted-hosts-canary",
    )
    monkeypatch.setattr(main, "load_hosts", lambda _settings: {host.public.id: host})
    monkeypatch.setattr(main, "list_samples", lambda: [dict(SAMPLE)])
    monkeypatch.setattr(main, "collect_replay", replay_fixture)
    checked = []

    def preflight(target):
        checked.append(target)
        return main.HostPreflight.model_validate(
            {
                "host_id": target.public.id,
                "status": "needs_attention",
                "connection": "ok",
                "platform": "compatible",
                "os_family": "ubuntu",
                "architecture": "x86_64",
                "missing_tools": [],
                "checks": [
                    {
                        "id": name,
                        "status": "permission_denied" if name == "container_state" else "ok",
                    }
                    for name in (
                        "os_release",
                        "platform_tools",
                        "nginx_status",
                        "container_state",
                        "disk_bytes",
                        "disk_inodes",
                        "compose_version",
                        "docker_rootful",
                    )
                ],
                "checked_at": datetime.now(UTC),
                "duration_ms": 30,
            }
        )

    monkeypatch.setattr(main, "run_host_preflight", preflight)
    application = main.create_app(settings_for(tmp_path))
    endpoint = "/api/hosts/lab/preflight"
    with TestClient(application) as client:
        assert client.get("/api/capabilities", headers=AUTH).json()["host_preflight"] is True
        assert client.post(endpoint, json={}).status_code == 401
        assert (
            client.post(
                endpoint, headers={**AUTH, "Origin": "https://other.invalid"}, json={}
            ).status_code
            == 403
        )
        assert client.post("/api/hosts/demo/preflight", headers=AUTH, json={}).status_code == 404
        assert client.post(endpoint, headers=AUTH, json={"command": "uptime"}).status_code == 422
        with application.state.investigation_lock:
            assert client.post(endpoint, headers=AUTH, json={}).status_code == 409
        assert checked == []

        response = client.post(endpoint, headers=AUTH, json={})
        assert response.status_code == 200 and checked == [host]
        assert response.headers["cache-control"] == "no-store"
        checks = {row["id"]: row["status"] for row in response.json()["checks"]}
        assert checks["container_state"] == "permission_denied" and checks["nginx_status"] == "ok"
        assert "private-key-canary" not in response.text
        assert "trusted-hosts-canary" not in response.text and "192.0.2.50" not in response.text
        assert client.get("/api/reports", headers=AUTH).json() == []
        assert client.get("/api/baselines", headers=AUTH).json() == []


def test_security_headers_and_repository_files_are_not_served(configured) -> None:
    client, _, _ = configured
    response = client.get("/api/status")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    for path in ["/docs/PRODUCT_PLAN.md", "/src/opsark/main.py", "/.git/config", "/openapi.json"]:
        assert client.get(path).status_code == 404
    assert client.get("/api/hosts", headers={**AUTH, "Host": "attacker.example"}).status_code == 400


@pytest.mark.parametrize(
    "origin", ["null", "https://attacker.example", "http://localhost", "http://testserver.evil"]
)
def test_cross_origin_investigations_are_rejected(configured, origin: str) -> None:
    client, _, _ = configured
    assert (
        client.post(
            "/api/investigations", headers={**AUTH, "Origin": origin}, json=REQUEST
        ).status_code
        == 403
    )
    assert client.get("/api/reports", headers=AUTH).json() == []


def test_same_origin_investigation_is_redacted_and_persisted(configured) -> None:
    client, application, settings = configured
    response = client.post(
        "/api/investigations", headers={**AUTH, "Origin": "http://testserver"}, json=REQUEST
    )
    assert response.status_code == 200
    report = response.json()
    assert report["source"] == "replay"
    assert report["action"]["executable"] is False
    assert "fixture-private-marker" not in response.text
    assert "fixture-private-marker" not in application.state.store.path.read_bytes().decode(
        "utf-8", errors="ignore"
    )
    assert client.get("/api/reports", headers=AUTH).json()[0]["id"] == report["id"]
    assert client.get(f"/api/reports/{report['id']}", headers=AUTH).json() == report
    reopened = main.create_app(settings)
    with TestClient(reopened) as other:
        assert other.get(f"/api/reports/{report['id']}", headers=AUTH).json() == report


@pytest.mark.parametrize(
    "change,code",
    [
        ({"command": "restart nginx"}, 422),
        ({"sample_id": "missing"}, 404),
        ({"scenario": "disk"}, 422),
        ({"sample_id": None}, 422),
        ({"host_id": "other-host"}, 422),
        ({"source": "ssh", "sample_id": None, "host_id": "unregistered"}, 404),
        ({"source": "ssh", "host_id": "unregistered"}, 422),
    ],
)
def test_unregistered_or_unexpected_investigation_input_is_rejected(
    configured, change, code: int
) -> None:
    client, _, _ = configured
    assert (
        client.post("/api/investigations", headers=AUTH, json={**REQUEST, **change}).status_code
        == code
    )
    assert client.get("/api/reports", headers=AUTH).json() == []


def test_busy_investigation_and_body_budget(configured) -> None:
    client, application, _ = configured
    application.state.investigation_lock.acquire()
    try:
        assert client.post("/api/investigations", headers=AUTH, json=REQUEST).status_code == 409
    finally:
        application.state.investigation_lock.release()
    assert client.post("/api/investigations", headers=AUTH, content="x" * 17_000).status_code == 413
    assert client.get("/api/reports", headers=AUTH).json() == []


def test_chunked_body_cannot_bypass_request_budget(configured) -> None:
    client, _, _ = configured

    def chunks():
        yield b'{"padding":"'
        yield b"x" * 17_000
        yield b'"}'

    response = client.post(
        "/api/investigations",
        headers={**AUTH, "Content-Type": "application/json"},
        content=chunks(),
    )
    assert response.status_code == 413
    assert client.get("/api/reports", headers=AUTH).json() == []


def test_validation_errors_do_not_reflect_inputs_or_context(configured) -> None:
    client, _, _ = configured
    response = client.post(
        "/api/investigations",
        headers=AUTH,
        json={**REQUEST, "private_key": "fixture-private-input-marker"},
    )
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)
    assert "fixture-private-input-marker" not in response.text
    assert "private_key" not in response.text
    assert "input" not in response.json()
    assert "ctx" not in response.json()


def test_unexpected_collection_exception_does_not_leak_paths_or_secret(
    configured, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, _ = configured

    def fail(sample_id):
        raise RuntimeError("private-key=/run/secrets/private-marker")

    monkeypatch.setattr(main, "collect_replay", fail)
    response = client.post("/api/investigations", headers=AUTH, json=REQUEST)
    assert response.status_code == 500
    assert "private-marker" not in response.text
    assert "private-key" not in response.text
    assert client.get("/api/reports", headers=AUTH).json() == []


def test_ssh_uses_registered_target_and_failed_check_is_not_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = HostPublic(id="vps-1", name="registered", address="192.0.2.20", source="ssh")
    registered = HostConfig(host, tmp_path / "private", tmp_path / "known")
    monkeypatch.setattr(main, "load_hosts", lambda settings: {host.id: registered})
    monkeypatch.setattr(main, "list_samples", lambda: [])
    monkeypatch.setattr(main, "diagnose", fake_diagnose)
    used = []

    def collect(target, scenario):
        used.append((target, scenario))
        return Collection(
            host_id=host.id,
            source="ssh",
            started_at=datetime.now(UTC),
            checks=[CheckResult(name="connection", status="permission_denied", exit_code=None)],
        )

    monkeypatch.setattr(main, "collect_ssh", collect)
    with TestClient(main.create_app(settings_for(tmp_path))) as client:
        response = client.post(
            "/api/investigations",
            headers=AUTH,
            json={
                "source": "ssh",
                "host_id": host.id,
                "scenario": "web_502",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "inconclusive"
        assert used == [(registered, "web_502")]
        hosts = client.get("/api/hosts", headers=AUTH).json()
        assert hosts[0]["id"] == host.id
        assert "key_file" not in str(hosts)
        assert "known_hosts_file" not in str(hosts)


def test_export_has_source_boundaries_and_missing_evidence(configured) -> None:
    client, _, _ = configured
    report = client.post("/api/investigations", headers=AUTH, json=REQUEST).json()
    response = client.get(f"/api/reports/{report['id']}/export", headers=AUTH)
    assert response.status_code == 200
    assert "回放样本" in response.text
    assert "没有已验收配置" in response.text
    assert "没有执行修复或封禁" in response.text
    assert "fixture-private-marker" not in response.text
    assert 'filename="opsark-report-1.md"' in response.headers["content-disposition"]
    assert client.get("/api/reports/not-found", headers=AUTH).status_code == 404


def test_customer_handoff_uses_saved_whitelist_without_touching_original(configured) -> None:
    client, application, _settings = configured
    host, collection = replay_fixture(SAMPLE["id"])
    report = fake_diagnose("web_502", host, collection)
    report.id = "internal-report-canary"
    report.host_name = "customer-internal-node.invalid"
    report.title = "Title canary"
    report.summary = "# forged heading"
    report.facts[0].text = "Legacy free text canary"
    report.evidence[0].id = "internal-evidence-canary"
    report.evidence[0].target = "192.0.2.189"
    report.evidence[0].output = "```\n# forged heading\nAuthorization: Bearer fake-token-canary"
    report.facts.append(
        Finding(
            text="目标站点的错误片段包含本机上游连接被拒绝，涉及端口 54321。",
            evidence_ids=[report.evidence[0].id],
        )
    )
    report.verification = [
        Verification(
            name="Private site check",
            detail="http://private.invalid/private-endpoint",
            status="passed",
            http_status=200,
        )
    ]
    report.comparison = BaselineComparison(
        status="compared",
        changes=[BaselineChange(field="internal-image", before="private:v1", after="private:v2")],
    )
    report.ai = AIExplanation(status="completed", text="AI narrative canary")
    application.state.store.save(report)
    report_url = f"/api/reports/{report.id}"
    before = client.get(report_url, headers=AUTH).json()

    assert client.get(report_url + "/handoff").status_code == 401
    assert client.get("/api/reports/not-found/handoff", headers=AUTH).status_code == 404
    handoff = client.get(report_url + "/handoff", headers=AUTH)
    assert handoff.status_code == 200
    assert handoff.headers["content-disposition"] == 'attachment; filename="opsark-handoff.md"'
    assert handoff.headers["cache-control"] == "no-store"
    assert "客户交接摘要" in handoff.text
    assert "回放样本" in handoff.text and "合成数据" in handoff.text
    assert "上游连接被拒绝（证据 1）" in handoff.text
    assert "200" in handoff.text and "未验收" in handoff.text
    for private in (
        report.id,
        report.host_name,
        report.title,
        report.summary,
        report.facts[0].text,
        report.evidence[0].id,
        report.evidence[0].target,
        "fake-token-canary",
        "54321",
        report.verification[0].name,
        report.verification[0].detail,
        "private:v2",
        report.ai.text,
        TOKEN,
    ):
        assert private not in handoff.text
    assert client.get(report_url, headers=AUTH).json() == before
    assert "AI narrative canary" in client.get(report_url + "/export", headers=AUTH).text


def test_customer_handoff_links_approved_original_and_later_recheck(configured) -> None:
    client, application, _settings = configured
    _, collection = replay_fixture(SAMPLE["id"])
    host = HostPublic(
        id="customer-node",
        name="private-host-name",
        address="192.0.2.48",
        source="ssh",
        health_checks=[HealthCheck(id="shop", domain="private.invalid", read_only_confirmed=True)],
    )
    scope = main.scope_for(host)
    report = fake_diagnose("web_502", host, collection.model_copy(update={"source": "ssh"}))
    report.target = host
    report.scope_hash = scope
    report.created_at = datetime.now(UTC) - timedelta(minutes=2)
    application.state.store.save(report)
    patches = application.state.patch_store
    job_id, plan_id, plan_digest, policy = "a" * 32, "b" * 32, "c" * 64, "d" * 64
    endpoint = f"/api/reports/{report.id}/handoff"
    assert client.get(endpoint + "-options", headers=AUTH).json() == {"jobs": [], "rechecks": []}
    assert patches.register_submission(
        host.id,
        job_id,
        plan_id,
        plan_digest,
        2,
        host_scope=scope,
        policy_digest=policy,
        authorization="assisted",
    )
    patches.mark_unknown(host.id, job_id, plan_id)
    waiting = client.get(endpoint, params={"job_id": job_id}, headers=AUTH)
    assert waiting.status_code == 200
    assert (
        "人工逐项批准" in waiting.text and "结果未知" in waiting.text and "待验收" in waiting.text
    )

    now = datetime.now(UTC).isoformat()
    result = {
        "schema_version": 1,
        "host_id": host.id,
        "job_id": job_id,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "policy_digest": policy,
        "mode_revision": 2,
        "authorization": "assisted",
        "status": "verified",
        "revision": 7,
        "install_exit_code": 0,
        "created_at": now,
        "updated_at": now,
        "detail": "private task log canary",
    }
    patches.save_job(
        host.id, result, from_status=True, current_host_scope=scope, current_policy_digest=policy
    )
    assert patches.get_handoff_audit(host.id, job_id)["reconciled_at"]
    pending = client.get(endpoint, params={"job_id": job_id}, headers=AUTH)
    assert pending.status_code == 200
    assert "查询原任务已核实结果" in pending.text and "待验收" in pending.text

    evidence = Evidence(
        id="E-HTTP-SHOP",
        check_id="http_shop",
        target=host.id,
        source="ssh",
        collected_at=datetime.now(UTC),
        status="ok",
        output="private HTTP body canary",
        exit_code=0,
    )
    recheck = report.model_copy(
        update={
            "id": "private-recheck-id",
            "created_at": datetime.now(UTC),
            "evidence": [evidence],
            "verification": [
                Verification(
                    name="站点即时检查：shop（private.invalid）",
                    status="passed",
                    detail="private note",
                    evidence_ids=[evidence.id],
                    http_status=200,
                    status_matches=True,
                    body_matches=True,
                )
            ],
        }
    )
    application.state.store.save(recheck)
    wrong_scope = recheck.model_copy(update={"id": "wrong-scope", "scope_hash": "f" * 64})
    application.state.store.save(wrong_scope)
    options = client.get(endpoint + "-options", headers=AUTH).json()
    assert [item["id"] for item in options["jobs"]] == [job_id]
    assert [item["id"] for item in options["rechecks"]] == [recheck.id]
    assert (
        client.get(
            endpoint, params={"job_id": job_id, "recheck_report_id": wrong_scope.id}, headers=AUTH
        ).status_code
        == 409
    )
    before = patches.get_job(host.id, job_id)
    handoff = client.get(
        endpoint, params={"job_id": job_id, "recheck_report_id": recheck.id}, headers=AUTH
    )
    assert handoff.status_code == 200 and "登记业务复验通过" in handoff.text
    for raw in (
        host.id,
        host.address,
        host.name,
        job_id,
        plan_id,
        plan_digest,
        recheck.id,
        "private.invalid",
        "private task log canary",
        evidence.output,
    ):
        assert raw not in handoff.text
    assert patches.get_job(host.id, job_id) == before


def test_handoff_recheck_runs_readonly_and_keeps_prior_results(tmp_path, monkeypatch):
    host = HostPublic(
        id="recheck-lab",
        name="private-lab-label",
        address="192.0.2.51",
        source="ssh",
        health_checks=[
            HealthCheck(
                id="shop",
                domain="private-check.invalid",
                path="/private-check",
                expected_body="private-expected-body",
                read_only_confirmed=True,
            )
        ],
    )
    registered = HostConfig(host, tmp_path / "key", tmp_path / "known-hosts")
    inventory = {host.id: registered}
    monkeypatch.setattr(main, "load_hosts", lambda _settings: inventory)
    mode = ["failed", "pending", "passed"]
    calls = []

    def collect(target, scenario):
        calls.append((target, scenario))
        result = mode.pop(0)
        check = CheckResult(name="http_shop", exit_code=0)
        if result == "pending":
            check.status = "timeout"
            check.exit_code = 28
            check.stderr = "private-collector-timeout"
        else:
            body = "private-expected-body" if result == "passed" else "private-wrong-body"
            check.stdout = body + "\nOPSARK_HTTP_STATUS:200\n"
        return Collection(
            source="ssh", host_id=host.id, started_at=datetime.now(UTC), checks=[check]
        )

    monkeypatch.setattr(main, "collect_ssh", collect)
    application = main.create_app(settings_for(tmp_path))
    _, sample = replay_fixture(SAMPLE["id"])
    original = fake_diagnose("web_502", host, sample.model_copy(update={"source": "ssh"}))
    original.target = host
    original.scope_hash = main.scope_for(host)
    original.created_at = datetime.now(UTC) - timedelta(minutes=1)
    application.state.store.save(original)
    patches = application.state.patch_store
    job_id, plan_id, plan_digest, policy = "a" * 32, "b" * 32, "c" * 64, "d" * 64
    assert patches.register_submission(
        host.id,
        job_id,
        plan_id,
        plan_digest,
        1,
        host_scope=original.scope_hash,
        policy_digest=policy,
        authorization="assisted",
    )
    patches.mark_unknown(host.id, job_id, plan_id)
    path = f"/api/reports/{original.id}/handoff-rechecks"
    payload = {"job_id": job_id}
    with TestClient(application) as client:
        assert client.get("/api/capabilities", headers=AUTH).json()["handoff_recheck"] is True
        assert client.post(path, json=payload).status_code == 401
        assert client.get(path, params=payload).status_code == 401
        assert client.post(path, headers=AUTH, json=payload).status_code == 409
        assert not calls

        now = datetime.now(UTC).isoformat()
        patches.save_job(
            host.id,
            {
                "schema_version": 1,
                "host_id": host.id,
                "job_id": job_id,
                "plan_id": plan_id,
                "plan_digest": plan_digest,
                "policy_digest": policy,
                "mode_revision": 1,
                "authorization": "assisted",
                "status": "verified",
                "revision": 7,
                "install_exit_code": 0,
                "created_at": now,
                "updated_at": now,
            },
            from_status=True,
            current_host_scope=original.scope_hash,
            current_policy_digest=policy,
        )
        original_job = patches.get_job(host.id, job_id)
        original_audit = patches.get_handoff_audit(host.id, job_id)
        initial = client.get(path, headers=AUTH, params=payload)
        assert initial.json() == {"can_run": True, "rechecks": []}
        wrong = client.post(path, headers=AUTH, json={"job_id": "f" * 32})
        assert wrong.status_code == 409
        malformed = client.post(path, headers=AUTH, json={**payload, "host_id": "private-input"})
        assert malformed.status_code == 422 and "private-input" not in malformed.text
        assert not calls

        rows = []
        artifacts = []
        for status, label in (
            ("failed", "复验未通过"),
            ("pending", "待验收"),
            ("passed", "登记业务复验通过"),
        ):
            response = client.post(path, headers=AUTH, json=payload)
            assert response.status_code == 201, response.text
            row = response.json()
            assert set(row) == {"id", "at", "status", "matched_checks", "configured_checks"}
            assert row["status"] == status and row["configured_checks"] == 1
            assert row["matched_checks"] == int(status == "passed")
            rows.append(row)
            for raw in (host.address, host.name, "private-check", "private-expected-body", job_id):
                assert raw not in response.text
            export_path = f"/api/reports/{original.id}/handoff"
            params = {**payload, "recheck_report_id": row["id"]}
            artifact = client.get(export_path, headers=AUTH, params=params)
            assert artifact.status_code == 200 and label in artifact.text
            assert "private-" not in artifact.text
            artifacts.append((params, artifact.content))
        assert client.get(path, headers=AUTH, params=payload).json() == {
            "can_run": True,
            "rechecks": rows[::-1],
        }
        assert len({row["id"] for row in rows}) == 3
        assert calls == [(registered, "web_502")] * 3

        inventory[host.id] = HostConfig(
            host.model_copy(update={"address": "192.0.2.52"}),
            registered.key_file,
            registered.known_hosts_file,
        )
        assert client.post(path, headers=AUTH, json=payload).status_code == 409
        inventory.clear()
        assert client.get(path, headers=AUTH, params=payload).json() == {
            "can_run": False,
            "rechecks": rows[::-1],
        }
        assert client.post(path, headers=AUTH, json=payload).status_code == 409
        for params, prior in artifacts:
            assert client.get(export_path, headers=AUTH, params=params).content == prior
        assert len(calls) == 3
        assert patches.get_job(host.id, job_id) == original_job
        assert patches.get_handoff_audit(host.id, job_id) == original_audit


def _save_reconciled_job(patches, report, native):
    patches.mark_unknown(report.host_id, native["job_id"], native["plan_id"])
    updated = {**native, "updated_at": datetime.now(UTC).isoformat()}
    patches.save_job(
        report.host_id,
        updated,
        from_status=True,
        current_host_scope=report.scope_hash,
        current_policy_digest=native["policy_digest"],
    )


def _register_handoff_job(patches, report, index):
    job_id, plan_id, plan_digest = f"{index:032x}", f"{index + 10:032x}", f"{index + 20:064x}"
    policy = "d" * 64
    assert patches.register_submission(
        report.host_id,
        job_id,
        plan_id,
        plan_digest,
        1,
        host_scope=report.scope_hash,
        policy_digest=policy,
        authorization="assisted",
    )
    native = {
        "schema_version": 1,
        "host_id": report.host_id,
        "job_id": job_id,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "policy_digest": policy,
        "mode_revision": 1,
        "authorization": "assisted",
        "status": "verified",
        "revision": 7,
        "install_exit_code": 0,
        "created_at": datetime.now(UTC).isoformat(),
    }
    _save_reconciled_job(patches, report, native)
    return native


@pytest.fixture
def business_handoff(tmp_path, monkeypatch):
    host = HostPublic(
        id="business-lab",
        name="private-host-name",
        address="192.0.2.51",
        source="ssh",
        health_checks=[
            HealthCheck(
                id="shop",
                domain="private-legacy.invalid",
                path="/private-legacy",
                expected_body="private-legacy-body",
                read_only_confirmed=True,
            )
        ],
    )
    registered = HostConfig(
        host,
        tmp_path / "private-key",
        tmp_path / "private-known-hosts",
        business_checks=tuple(
            BusinessCheck(
                id=check,
                domain="private-receipt.invalid",
                path=f"/private-{check}",
                expected_body_sha256="e" * 64,
                read_only_confirmed=True,
            )
            for check in ("static", "application")
        ),
    )
    inventory = {host.id: registered}
    monkeypatch.setattr(main, "load_hosts", lambda _settings: inventory)
    monkeypatch.setattr(main, "collect_ssh", lambda *_args: pytest.fail("legacy SSH was called"))
    monkeypatch.setattr(main, "explain", lambda *_args: pytest.fail("AI was called"))
    app = main.create_app(
        settings_for(
            tmp_path,
            ai_base_url="https://model.invalid/v1",
            ai_key="synthetic-key",
            ai_model="fixture",
        )
    )
    _, sample = replay_fixture(SAMPLE["id"])
    report = fake_diagnose("web_502", host, sample.model_copy(update={"source": "ssh"}))
    report.target = host
    report.scope_hash = main.scope_for(host)
    report.created_at = datetime.now(UTC) - timedelta(minutes=1)
    app.state.store.save(report)
    patches = app.state.patch_store
    native = _register_handoff_job(patches, report, 1)
    return app, inventory, registered, report, native


def _business_result(host_id, status):
    def passed(check):
        return BusinessCheckResult(
            id=check,
            status="passed",
            http_status=200,
            status_matches=True,
            body_matches=True,
        )

    if status == "failed":
        app = BusinessCheckResult(
            id="application", status="failed", http_status=503, status_matches=False
        )
    elif status == "inconclusive":
        app = BusinessCheckResult(id="application", status="inconclusive")
    else:
        app = passed("application")
    return BusinessReadiness(host_id=host_id, status=status, checks=[passed("static"), app])


def test_handoff_business_receipts_are_private_scoped_and_stable(business_handoff, monkeypatch):
    app, inventory, registered, original, native = business_handoff
    patches = app.state.patch_store
    job_id = native["job_id"]
    other_job_id = _register_handoff_job(patches, original, 2)["job_id"]
    other = original.model_copy(update={"id": "another-original-same-scope"})
    app.state.store.save(other)
    evidence = Evidence(
        id="E-HTTP-SHOP",
        check_id="http_shop",
        target=original.host_id,
        source="ssh",
        collected_at=datetime.now(UTC),
        status="ok",
        output="private-legacy-body",
        exit_code=0,
    )
    legacy = original.model_copy(
        update={
            "id": "legacy-report",
            "created_at": datetime.now(UTC),
            "evidence": [evidence],
            "verification": [
                Verification(
                    name="站点即时检查：shop（private-legacy.invalid）",
                    status="passed",
                    detail="private-note",
                    evidence_ids=[evidence.id],
                    http_status=200,
                    status_matches=True,
                    body_matches=True,
                )
            ],
        }
    )
    app.state.store.save(legacy)
    results = iter(("failed", "inconclusive", "passed"))
    collected = []

    def run_business(host):
        collected.append(host)
        return _business_result(host.public.id, next(results))

    monkeypatch.setattr(main, "run_business_readiness", run_business)
    handoff = f"/api/reports/{original.id}/handoff"
    rechecks = handoff + "-rechecks"
    job = {"job_id": job_id}
    patch_before = patches.get_job(original.host_id, job_id)
    audit_before = patches.get_handoff_audit(original.host_id, job_id)
    with TestClient(app, headers=AUTH) as client:
        assert client.get("/api/ai/status").json()["configured"] is True
        assert client.post(rechecks, headers={"Authorization": ""}, json=job).status_code == 401
        reports_before = client.get("/api/reports").json()
        prior_params = {**job, "recheck_report_id": legacy.id}
        prior = client.get(handoff, params=prior_params)
        assert prior.status_code == 200 and "登记业务复验通过" in prior.text
        history_before = client.get(rechecks, params=job).json()
        assert history_before["can_run"] is True
        assert [row["id"] for row in history_before["rechecks"]] == [legacy.id]
        rows, saved_exports = [], []
        for status, count, label in (
            ("failed", 1, "复验未通过"),
            ("pending", 1, "待验收"),
            ("passed", 2, "登记业务复验通过"),
        ):
            response = client.post(rechecks, json=job)
            assert response.status_code == 201, response.text
            row = response.json()
            assert re.fullmatch(r"br-[0-9a-f]{32}", row["id"])
            assert row == {
                "id": row["id"],
                "at": row["at"],
                "status": status,
                "configured_checks": 2,
                "matched_checks": count,
            }
            rows.append(row)
            assert client.get(f"/api/reports/{row['id']}").status_code == 404
            params = {**job, "recheck_report_id": row["id"]}
            artifact = client.get(handoff, params=params)
            assert artifact.status_code == 200 and label in artifact.text
            for secret in ("private-", "192.0.2.51", "e" * 64, job_id, row["id"]):
                assert secret not in artifact.text
            assert re.search(r"\b503\b", artifact.text) is None
            saved_exports.append((params, artifact.content))

        assert len({row["id"] for row in rows}) == 3
        assert collected == [registered] * 3
        assert client.get("/api/reports").json() == reports_before
        receipts = app.state.store.handoff_receipts(original.id, job_id)
        assert [receipt.checks for receipt in receipts] == [
            ["passed", "passed"],
            ["passed", "inconclusive"],
            ["passed", "failed"],
        ]
        for receipt in receipts:
            document = receipt.model_dump_json()
            for private in ("private-", "e" * 64, "http_status", "stdout", "stderr"):
                assert private not in document
        history = rows[::-1] + history_before["rechecks"]
        assert client.get(rechecks, params=job).json() == {"can_run": True, "rechecks": history}
        for wrong_handoff, wrong_job in (
            (handoff, other_job_id),
            (f"/api/reports/{other.id}/handoff", job_id),
        ):
            params = {"job_id": wrong_job, "recheck_report_id": rows[-1]["id"]}
            assert client.get(wrong_handoff, params=params).status_code in (404, 409)
            unrelated = client.get(wrong_handoff + "-rechecks", params={"job_id": wrong_job})
            assert unrelated.status_code == 200
            assert not {row["id"] for row in unrelated.json()["rechecks"]}.intersection(
                row["id"] for row in rows
            )

        changed = registered.business_checks[1].model_copy(
            update={
                "path": "/private-new-origin",
                "expected_body_sha256": "f" * 64,
            }
        )
        inventory[original.host_id] = replace(
            registered,
            business_checks=(registered.business_checks[0], changed),
        )
        assert client.get(rechecks, params=job).json() == {"can_run": True, "rechecks": history}
        inventory[original.host_id] = replace(registered, business_checks=())
        assert client.get(rechecks, params=job).json() == {"can_run": False, "rechecks": history}
        assert client.post(rechecks, json=job).status_code == 409
        inventory.clear()
        assert client.get(rechecks, params=job).json() == {"can_run": False, "rechecks": history}
        for params, content in [*saved_exports, (prior_params, prior.content)]:
            assert client.get(handoff, params=params).content == content
        assert patches.get_job(original.host_id, job_id) == patch_before
        assert patches.get_handoff_audit(original.host_id, job_id) == audit_before


def test_handoff_business_receipt_refuses_later_reconciliation(business_handoff, monkeypatch):
    app, _, _, original, native = business_handoff
    patches = app.state.patch_store
    job = {"job_id": native["job_id"]}
    path = f"/api/reports/{original.id}/handoff-rechecks"
    prior = patches.get_handoff_audit(original.host_id, native["job_id"])
    calls = []

    def race(host):
        calls.append(host.public.id)
        _save_reconciled_job(patches, original, {**native, "revision": 8})
        return _business_result(host.public.id, "passed")

    monkeypatch.setattr(main, "run_business_readiness", race)
    with TestClient(app, headers=AUTH) as client:
        assert client.get(path, params=job).json() == {"can_run": True, "rechecks": []}
        refused = client.post(path, json=job)
        assert refused.status_code == 409
        assert calls == [original.host_id]
        after = patches.get_handoff_audit(original.host_id, native["job_id"])
        assert after["reconciled_revision"] == 8
        assert after["reconciled_at"] > prior["reconciled_at"]
        assert client.get(path, params=job).json() == {"can_run": True, "rechecks": []}
        assert app.state.store.handoff_receipts(original.id, native["job_id"]) == []
        assert [row["id"] for row in client.get("/api/reports").json()] == [original.id]


def test_ai_requires_configuration_and_explicit_consent(configured) -> None:
    client, _, _ = configured
    report = client.post("/api/investigations", headers=AUTH, json=REQUEST).json()
    endpoint = f"/api/reports/{report['id']}/explain"
    assert client.post(endpoint, headers=AUTH, json={"confirm_send": False}).status_code == 422
    assert client.post(endpoint, headers=AUTH, json={"confirm_send": True}).status_code == 409
    assert (
        client.get(f"/api/reports/{report['id']}", headers=AUTH).json()["ai"]["status"]
        == "not_requested"
    )


def test_ai_explanation_preserves_report_and_handles_provider_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main, "load_hosts", lambda settings: {})
    monkeypatch.setattr(main, "list_samples", lambda: [dict(SAMPLE)])
    monkeypatch.setattr(main, "collect_replay", replay_fixture)
    monkeypatch.setattr(main, "diagnose", fake_diagnose)
    settings = settings_for(
        tmp_path, ai_base_url="https://model.example/v1", ai_key="test-key", ai_model="test-model"
    )
    with TestClient(main.create_app(settings)) as client:
        before = client.post("/api/investigations", headers=AUTH, json=REQUEST).json()
        endpoint = f"/api/reports/{before['id']}/explain"
        monkeypatch.setattr(
            main,
            "explain",
            lambda report, settings: AIExplanation(
                status="completed",
                text="仅补充解释",
                evidence_ids=["e1"],
                model="test-model",
            ),
        )
        assert (
            client.post(endpoint, headers=AUTH, json={"confirm_send": True}).json()["status"]
            == "completed"
        )
        after = client.get(f"/api/reports/{before['id']}", headers=AUTH).json()
        assert {k: v for k, v in before.items() if k != "ai"} == {
            k: v for k, v in after.items() if k != "ai"
        }

        def failure(report, settings):
            raise RuntimeError("provider-secret-marker")

        monkeypatch.setattr(main, "explain", failure)
        failed = client.post(endpoint, headers=AUTH, json={"confirm_send": True})
        assert failed.json()["status"] == "failed"
        assert "provider-secret-marker" not in failed.text
        assert (
            client.get(f"/api/reports/{before['id']}", headers=AUTH).json()["action"]["executable"]
            is False
        )


def test_markdown_export_cannot_close_its_own_log_fence() -> None:
    host, collection = replay_fixture(SAMPLE["id"])
    report = fake_diagnose("web_502", host, collection)
    report.evidence[0].output = "```\n# forged section\n<script>not execution</script>"
    report.summary = "line one\n# forged heading"
    result = main.report_markdown(report)
    assert "````text" in result
    assert "\n# forged heading" not in result
    assert "\\# forged heading" in result
