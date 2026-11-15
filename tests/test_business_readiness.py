"""Keep registered business probes outside investigation and model evidence."""

import hashlib
import shlex
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from opsark import business_readiness, collector, main
from opsark.config import Settings, load_hosts
from opsark.models import CheckResult
from opsark.nginx_dependencies import path_observation_binding_digest

_DIGEST = hashlib.sha256(b"opsark-origin-fixture\n").hexdigest()
_CANARY = "synthetic-private-response-canary"
_TOKEN = "test-business-readiness-token-0123456789"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}
_ENDPOINT = "/api/hosts/lab/business-readiness"
_NGINX_ENDPOINT = "/api/hosts/lab/nginx-path-observation"
_NGINX_REGISTRATION = f'compose_project = "lab"\nnginx_dependency_scope_digest = "{"a" * 64}"'
_MATCH = "OPSARK_HTTP_READINESS_V1 200 match\n"


def settings_for(tmp_path, *, second="", username="opsark-readonly", nginx=""):
    inventory = tmp_path / "hosts.toml"
    (tmp_path / "test-key").touch()
    (tmp_path / "test-known").write_text("synthetic host key fixture\n", encoding="ascii")
    inventory.write_text(
        f"""
[credentials.lab]
key_file = "test-key"
known_hosts_file = "test-known"
[[hosts]]
id = "lab"
address = "127.0.0.1"
username = "{username}"
site_domain = "fixture.invalid"
credential = "lab"
{nginx}
[[hosts.business_checks]]
id = "business"
domain = "fixture.invalid"
port = 18080
path = "/public/readiness"
expected_body_sha256 = "{_DIGEST}"
read_only_confirmed = true
{second}
""",
        encoding="ascii",
    )
    return Settings(data_dir=tmp_path / "data", token=_TOKEN, inventory_path=inventory)


def test_business_route_is_registered_only_and_emits_no_private_evidence(tmp_path, monkeypatch):
    settings = settings_for(tmp_path)
    requested = []

    def collect(host, commands):
        requested.append(host.public.id)
        assert set(commands) == {"business_business"}
        assert shlex.split(commands["business_business"]) == [
            "timeout",
            "-k",
            "1s",
            "5s",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/usr/local/libexec/opsark-http-readiness",
            "fixture.invalid",
            "18080",
            "/public/readiness",
            "200",
            _DIGEST,
        ]
        return {"business_business": CheckResult(name="business_business", stdout=_MATCH + _CANARY)}

    monkeypatch.setattr(business_readiness, "collect_business_receipts", collect)
    monkeypatch.setattr(main, "explain", lambda *_a, **_k: pytest.fail("readiness invoked AI"))
    app = main.create_app(settings)
    with TestClient(app) as client:
        assert client.post(_ENDPOINT, json={}).status_code == 401
        rejected = client.post(_ENDPOINT, headers=_AUTH, json={"path": _CANARY})
        assert rejected.status_code == 422 and _CANARY not in rejected.text
        assert (
            client.post("/api/hosts/unknown/business-readiness", headers=_AUTH, json={}).status_code
            == 404
        )
        with app.state.investigation_lock:
            assert client.post(_ENDPOINT, headers=_AUTH, json={}).status_code == 409
        assert not requested
        response = client.post(_ENDPOINT, headers=_AUTH, json={})
        assert response.status_code == 200 and requested == ["lab"]
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "host_id": "lab",
            "status": "inconclusive",
            "checks": [
                {
                    "id": "business",
                    "status": "inconclusive",
                    "http_status": None,
                    "status_matches": None,
                    "body_matches": None,
                }
            ],
        }
        for marker in (
            _CANARY,
            _DIGEST,
            "fixture.invalid",
            "/public/readiness",
            "stdout",
            "stderr",
        ):
            assert marker not in response.text
        assert client.get("/api/reports", headers=_AUTH).json() == []
        assert client.get("/api/baselines", headers=_AUTH).json() == []


def test_nginx_path_observation_reuses_private_registered_probe(tmp_path, monkeypatch):
    settings = settings_for(tmp_path, nginx=_NGINX_REGISTRATION)
    samples = iter(
        (
            CheckResult(
                name="business_business", stdout="OPSARK_HTTP_READINESS_V1 200 body_mismatch\n"
            ),
            CheckResult(name="business_business", status="timeout", exit_code=None, stderr=_CANARY),
            CheckResult(name="business_business", stdout=_MATCH),
        )
    )
    requested = []

    def collect(host, commands):
        requested.append(host.public.id)
        assert list(commands) == ["business_business"]
        assert shlex.split(commands["business_business"])[7:] == [
            "/usr/local/libexec/opsark-http-readiness",
            "fixture.invalid",
            "18080",
            "/public/readiness",
            "200",
            _DIGEST,
        ]
        return {"business_business": next(samples)}

    monkeypatch.setattr(business_readiness, "collect_business_receipts", collect)
    monkeypatch.setattr(
        main, "explain", lambda *_a, **_k: pytest.fail("path observation invoked AI")
    )
    monkeypatch.setattr(
        main, "run_nginx_dependencies", lambda *_a: pytest.fail("path observation read disk config")
    )
    app = main.create_app(settings)
    with TestClient(app) as client:
        host = next(
            row for row in client.get("/api/hosts", headers=_AUTH).json() if row["id"] == "lab"
        )
        binding = host["nginx_path_observation_binding_digest"]
        assert binding == path_observation_binding_digest(load_hosts(settings)["lab"])
        assert client.post(_NGINX_ENDPOINT, json={}).status_code == 401
        rejected = client.post(_NGINX_ENDPOINT, headers=_AUTH, json={"path": _CANARY})
        assert rejected.status_code == 422 and _CANARY not in rejected.text
        assert (
            client.post(
                _NGINX_ENDPOINT.replace("/lab/", "/missing/"), headers=_AUTH, json={}
            ).status_code
            == 404
        )
        with app.state.investigation_lock:
            assert client.post(_NGINX_ENDPOINT, headers=_AUTH, json={}).status_code == 409
        assert requested == []

        for status, code, status_matches, body_matches in (
            ("failed", 200, True, False),
            ("inconclusive", None, None, None),
            ("passed", 200, True, True),
        ):
            response = client.post(_NGINX_ENDPOINT, headers=_AUTH, json={})
            assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
            assert response.json() == {
                "host_id": "lab",
                "binding_digest": binding,
                "observed_at": response.json()["observed_at"],
                "status": status,
                "checks": [
                    {
                        "id": "business",
                        "status": status,
                        "http_status": code,
                        "status_matches": status_matches,
                        "body_matches": body_matches,
                    }
                ],
            }
            assert response.json()["observed_at"].endswith("Z")
            for forbidden in (
                _CANARY,
                _DIGEST,
                "fixture.invalid",
                "/public/readiness",
                "loaded_generation",
            ):
                assert forbidden not in response.text
        assert requested == ["lab"] * 3
        assert client.get("/api/reports", headers=_AUTH).json() == []
        assert client.get("/api/baselines", headers=_AUTH).json() == []


def test_nginx_path_binding_tracks_scope_and_private_registration(tmp_path):
    target = load_hosts(settings_for(tmp_path, nginx=_NGINX_REGISTRATION))["lab"]
    check = target.business_checks[0]
    original = path_observation_binding_digest(target)
    assert original
    assert path_observation_binding_digest(replace(target, nginx_scope_digest=None)) is None
    assert path_observation_binding_digest(replace(target, compose_project=None)) is None
    unpinned = target.public.model_copy(update={"trusted_hosts_digest": None})
    assert path_observation_binding_digest(replace(target, public=unpinned)) is None
    assert path_observation_binding_digest(replace(target, nginx_scope_digest="b" * 64)) != original
    assert path_observation_binding_digest(replace(target, business_checks=())) is None
    for changes in ({"path": "/different"}, {"expected_body_sha256": "b" * 64}):
        updated = replace(target, business_checks=(check.model_copy(update=changes),))
        assert path_observation_binding_digest(updated) != original
    unconfirmed = replace(
        target, business_checks=(check.model_copy(update={"read_only_confirmed": False}),)
    )
    assert path_observation_binding_digest(unconfirmed) is None


def test_nginx_path_observation_unavailable_for_generic_business_only_host(tmp_path, monkeypatch):
    monkeypatch.setattr(
        business_readiness,
        "collect_business_receipts",
        lambda *_a: pytest.fail("unregistered probe"),
    )
    with TestClient(main.create_app(settings_for(tmp_path))) as client:
        hosts = client.get("/api/hosts", headers=_AUTH).json()
        assert all("nginx_path_observation_binding_digest" not in row for row in hosts)
        assert client.post(_NGINX_ENDPOINT, headers=_AUTH, json={}).status_code == 409


@pytest.mark.parametrize(
    ("wire", "extra", "expected"),
    [
        (_MATCH, {}, ("passed", 200, True, True)),
        ("OPSARK_HTTP_READINESS_V1 502 status_mismatch\n", {}, ("failed", 502, False, None)),
        ("OPSARK_HTTP_READINESS_V1 200 body_mismatch\n", {}, ("failed", 200, True, False)),
        ("OPSARK_HTTP_READINESS_V1 inconclusive\n", {}, ("inconclusive", None, None, None)),
        ("OPSARK_HTTP_READINESS_V1 200 status_mismatch\n", {}, ("inconclusive", None, None, None)),
        ("OPSARK_HTTP_READINESS_V1 502 match\n", {}, ("inconclusive", None, None, None)),
        (_MATCH, {"truncated": True}, ("inconclusive", None, None, None)),
        (_MATCH, {"stderr": _CANARY}, ("inconclusive", None, None, None)),
        (_MATCH, {"status": "timeout", "exit_code": None}, ("inconclusive", None, None, None)),
        (_MATCH, {"exit_code": None}, ("inconclusive", None, None, None)),
    ],
)
def test_receipt_requires_complete_matching_fixed_evidence(tmp_path, wire, extra, expected):
    check = load_hosts(settings_for(tmp_path))["lab"].business_checks[0]
    row = business_readiness._evaluate(
        check, CheckResult(name="business_business", stdout=wire, **extra)
    )
    assert (row.status, row.http_status, row.status_matches, row.body_matches) == expected


def test_unconfirmed_probe_is_uncovered_and_failure_takes_precedence(tmp_path, monkeypatch):
    settings = settings_for(
        tmp_path,
        second=f'''
[[hosts.business_checks]]
id = "unconfirmed"
domain = "fixture.invalid"
path = "/unconfirmed"
expected_body_sha256 = "{_DIGEST}"
[[hosts.business_checks]]
id = "other"
domain = "fixture.invalid"
path = "/other"
expected_body_sha256 = "{_DIGEST}"
read_only_confirmed = true
''',
    )
    host = load_hosts(settings)["lab"]
    assert "business_checks" not in host.public.model_dump()

    def collect(_host, commands):
        assert set(commands) == {"business_business", "business_other"}
        return {
            "business_business": CheckResult(
                name="business_business", stdout="OPSARK_HTTP_READINESS_V1 502 status_mismatch\n"
            )
        }

    monkeypatch.setattr(business_readiness, "collect_business_receipts", collect)
    result = business_readiness.run_business_readiness(host)
    assert result.status == "failed"
    assert [row.status for row in result.checks] == ["failed", "uncovered", "inconclusive"]


def test_cannot_register_same_endpoint_for_legacy_body_collection(tmp_path):
    settings = settings_for(
        tmp_path,
        second="""
[[hosts.health_checks]]
id = "legacy"
domain = "Fixture.Invalid"
port = 18080
path = "/public/readiness"
read_only_confirmed = true
""",
    )
    with pytest.raises(ValueError, match="旧版站点正文采集"):
        load_hosts(settings)


def test_business_checks_require_dedicated_account(tmp_path):
    with pytest.raises(ValueError, match="opsark-readonly"):
        load_hosts(settings_for(tmp_path, username="other-reader"))


def test_host_pin_drift_is_refused_before_business_command(tmp_path, monkeypatch):
    host = load_hosts(settings_for(tmp_path))["lab"]
    host.known_hosts_file.write_text("changed\n", encoding="ascii")
    monkeypatch.setattr(
        collector.paramiko.SSHClient, "connect", lambda *_a, **_k: pytest.fail("untrusted SSH")
    )
    assert business_readiness.run_business_readiness(host).status == "inconclusive"


def test_empty_registration_never_opens_ssh(tmp_path, monkeypatch):
    host = replace(load_hosts(settings_for(tmp_path))["lab"], business_checks=())
    monkeypatch.setattr(
        collector.paramiko.SSHClient, "connect", lambda *_a, **_k: pytest.fail("unneeded SSH")
    )
    assert business_readiness.run_business_readiness(host).model_dump() == {
        "host_id": "lab",
        "status": "uncovered",
        "checks": [],
    }


def test_malformed_registered_host_key_is_inconclusive_without_diagnostics(tmp_path, monkeypatch):
    settings = settings_for(tmp_path)
    (tmp_path / "test-known").write_text("127.0.0.1 ssh-ed25519 Z\n", encoding="ascii")
    host = load_hosts(settings)["lab"]
    monkeypatch.setattr(
        collector.paramiko.SSHClient, "connect", lambda *_a, **_k: pytest.fail("untrusted SSH")
    )
    result = business_readiness.run_business_readiness(host)
    assert result.status == "inconclusive"
    assert "ssh-ed25519" not in result.model_dump_json()
