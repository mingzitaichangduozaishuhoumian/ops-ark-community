"""Synthetic projection and transport contract; no real SSH, Docker or model call."""

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from deploy.readonly import nginx_dependencies as helper
from opsark import nginx_dependencies as discovery
from opsark.collector import nginx_dependencies_command
from opsark.compose_discovery import project_compose_discovery
from opsark.config import HostConfig, Settings
from opsark.models import CheckResult, HostPublic
from opsark.platforms import TOOLS

NOW = datetime(2026, 11, 7, tzinfo=UTC)
ENTRY = "/etc/nginx/nginx.conf"
SITE = "/etc/nginx/sites-enabled/demo.conf"


def scope(**updates):
    return helper.canonical(
        {
            "schema_version": 1,
            "entry": ENTRY,
            "include_files": [],
            "include_roots": ["/etc/nginx/sites-enabled"],
            "symlink_roots": ["/etc/nginx/sites-available"],
            "compose_project": "demo",
        }
        | updates
    )


def server(domain="a.example.test", upstream="http://127.0.0.1:8081", extra="", location="/"):
    return (
        f"server {{ listen 80; server_name {domain}; {extra} "
        f"location {location} {{ proxy_pass {upstream}; }} }}\n"
    ).encode()


def projection(site=None, **files):
    contents = {
        ENTRY: b"events {} http { include /etc/nginx/sites-enabled/*.conf; }\n",
        SITE: server() if site is None else site,
    } | files
    return helper.project(
        scope(),
        contents.__getitem__,
        lambda pattern: sorted(
            p for p in contents if p.startswith("/etc/nginx/sites-enabled/") and p.endswith(".conf")
        ),
    )


def host(tmp_path):
    return HostConfig(
        public=HostPublic(id="fixture", name="fixture", address="192.0.2.10", source="ssh"),
        key_file=tmp_path / "synthetic-key-reference",
        known_hosts_file=tmp_path / "synthetic-pin-reference",
        compose_project="demo",
        container_binding_confirmed=False,
        nginx_scope_digest=helper.digest(scope()),
    )


def settings(tmp_path):
    return Settings(data_dir=tmp_path / "fake-controller", token="synthetic-nginx-console-token")


def parsed(tmp_path, value=None):
    return discovery.parse_projection(
        CheckResult(
            name="nginx_dependencies", stdout=json.dumps(projection() if value is None else value)
        ),
        host(tmp_path),
        settings(tmp_path),
    )


def compose(tmp_path, *, ports="127.0.0.1:8081->8000/tcp", duplicate=False):
    rows = [
        {
            "id": "a" * 64,
            "name": "demo-api-1",
            "state": "running",
            "project": "demo",
            "service": "api",
            "ports": ports,
        }
    ]
    if duplicate:
        rows.append(rows[0] | {"id": "b" * 64, "name": "demo-api-2"})
    return project_compose_discovery(
        host(tmp_path),
        "demo",
        CheckResult(name="compose_inventory", stdout="\n".join(json.dumps(v) for v in rows)),
        collected_at=NOW,
        duration_ms=0,
    )


def joined(tmp_path, value=None, **kwargs):
    return discovery.project_dependencies(
        host(tmp_path),
        parsed(tmp_path, value),
        compose(tmp_path, **kwargs),
        collected_at=NOW,
        duration_ms=1,
    )


def test_literal_chain_is_automatic_without_container_registration(tmp_path):
    value = joined(tmp_path)
    assert value.status == "observed" and value.loaded_generation == "unknown"
    assert value.actions_enabled is False and value.model_calls == 0
    assert value.relationships[0].binding == "unique"
    assert value.relationships[0].service_name == "api"
    assert value.relationships[0].domains == ["a.example.test"]
    assert value.relationships[0].file == SITE and value.files[0].sha256


def test_two_sites_share_upstream_and_service_automatically(tmp_path):
    value = joined(tmp_path, projection(server() + server("b.example.test")))
    assert {item.kind for item in value.shared_dependencies} == {"upstream", "compose_service"}
    assert all(
        item.domains == ["a.example.test", "b.example.test"] for item in value.shared_dependencies
    )


@pytest.mark.parametrize(
    "ports,binding",
    [
        ("0.0.0.0:8081->8000/tcp", "unique"),
        ("[::]:8081->8000/tcp", "unmatched"),
        ("[::1]:8081->8000/tcp", "unmatched"),
        ("127.0.0.1:8082->8000/tcp", "unmatched"),
        ("127.0.0.1:8081->8000/udp", "unmatched"),
        ("8081/tcp", "unmatched"),
    ],
)
def test_ip_family_protocol_and_publication_are_part_of_identity(tmp_path, ports, binding):
    assert joined(tmp_path, ports=ports).relationships[0].binding == binding


def test_multiple_candidates_and_duplicate_virtual_host_do_not_bind(tmp_path):
    assert joined(tmp_path, duplicate=True).relationships[0].binding == "ambiguous"
    value = joined(tmp_path, projection(server() + server()))
    assert all(edge.binding == "unsupported" for edge in value.relationships)
    assert value.shared_dependencies == []


def test_named_upstream_members_have_separate_evidence(tmp_path):
    config = b"upstream backend { server 127.0.0.1:8081; server [::1]:8082; }\n" + server(
        upstream="http://backend"
    )
    value = joined(tmp_path, projection(config))
    assert [
        (edge.endpoint.ip, edge.endpoint.port, edge.binding) for edge in value.relationships
    ] == [("127.0.0.1", 8081, "unique"), ("::1", 8082, "unmatched")]


@pytest.mark.parametrize(
    "upstream,extra,location",
    [
        ("http://$backend", "", "/"),
        ("http://external.example.test:8081", "", "/"),
        ("http://unix:/run/backend.sock:", "", "/"),
        ("http://127.0.0.1:8081", "rewrite ^ /elsewhere;", "/"),
        ("http://127.0.0.1:8081", "", "~ /regex"),
    ],
)
def test_nonliteral_or_semantically_changed_routing_is_unknown(tmp_path, upstream, extra, location):
    value = joined(tmp_path, projection(server(upstream=upstream, extra=extra, location=location)))
    assert value.relationships[0].binding == "unsupported"


@pytest.mark.parametrize(
    "canary",
    [
        "# api_key = synthetic-canary\n",
        "# -----BEGIN OPENSSH PRIVATE KEY-----\n",
        "# SELECT secret FROM customer_table;\n",
        "proxy_set_header Authorization 'Bearer synthetic-canary';",
    ],
)
def test_sensitive_configuration_blocks_the_entire_projection(canary):
    with pytest.raises(helper.Refused, match="content_blocked"):
        projection(server(extra=canary))


@pytest.mark.parametrize(
    "change", ["extra", "route_extra", "schema", "scope", "project", "external", "digest"]
)
def test_unknown_or_unbound_remote_metadata_is_not_partially_accepted(tmp_path, change):
    value = projection()
    if change == "extra":
        value["headers"] = "synthetic-canary"
    elif change == "route_extra":
        value["servers"][0]["routes"][0]["unknown"] = True
    elif change == "schema":
        value["schema"] = "untrusted"
    elif change == "scope":
        value["scope_digest"] = "0" * 64
    elif change == "project":
        value["project"] = "other"
    elif change == "external":
        value["servers"][0]["routes"][0]["endpoints"][0]["ip"] = "192.0.2.99"
    else:
        value["snapshot_digest"] = "0" * 64
    if change != "digest":
        value["snapshot_digest"] = discovery._digest(
            {k: v for k, v in value.items() if k != "snapshot_digest"}
        )
    with pytest.raises(ValueError, match="projection rejected"):
        parsed(tmp_path, value)


def test_comment_or_quoted_braces_do_not_invent_a_server(tmp_path):
    value = projection(
        server(extra="add_header X-Brace '{'; # server { proxy_pass http://127.0.0.1:9999; }\n")
    )
    assert len(parsed(tmp_path, value).servers) == 1


def test_includes_outside_scope_cycles_and_limits_are_refused():
    for config in (
        b"http { include /etc/passwd; }\n",
        b"http { include /etc/nginx/nginx.conf; }\n",
        b"http { include /etc/nginx/private.key; }\n",
    ):
        with pytest.raises(helper.Refused):
            helper.project(scope(), lambda _, config=config: config, lambda pattern: [pattern])
    with pytest.raises(helper.Refused, match="configuration_limit"):
        helper.parse(b"x" * (helper.MAX_BYTES + 1), ENTRY)


def test_exact_command_has_no_api_or_model_parameters(tmp_path):
    assert (
        nginx_dependencies_command(host(tmp_path))
        == "timeout -k 1s 5s /usr/local/libexec/opsark-nginx-dependencies"
    )
    with pytest.raises(ValueError):
        nginx_dependencies_command(replace(host(tmp_path), nginx_scope_digest=None))


def test_no_reload_does_not_become_loaded_generation_or_actions(tmp_path):
    old, changed = (
        joined(tmp_path),
        joined(tmp_path, projection(server(upstream="http://127.0.0.1:8082"))),
    )
    assert old.snapshot_digest != changed.snapshot_digest
    assert changed.loaded_generation == "unknown" and changed.actions_enabled is False
    assert changed.relationships[0].binding == "unmatched"


def test_registered_scope_and_project_are_part_of_public_binding_identity(tmp_path):
    target = host(tmp_path)
    before = discovery.dependency_binding_digest(target)
    assert before == discovery.dependency_binding_digest(target)
    assert before != discovery.dependency_binding_digest(
        replace(target, nginx_scope_digest="b" * 64)
    )
    assert before != discovery.dependency_binding_digest(replace(target, compose_project="other"))
    assert before != discovery.dependency_binding_digest(
        replace(target, public=target.public.model_copy(update={"trusted_hosts_digest": "c" * 64}))
    )
    assert joined(tmp_path).binding_digest == before


def test_incomplete_transport_discards_all_remote_rows(tmp_path):
    for updates in (
        {"truncated": True},
        {"status": "timeout", "exit_code": None},
        {"stderr": "synthetic-canary"},
    ):
        check = CheckResult(name="nginx_dependencies", stdout=json.dumps(projection())).model_copy(
            update=updates
        )
        with pytest.raises(ValueError):
            discovery.parse_projection(check, host(tmp_path), settings(tmp_path))


def test_duplicate_json_and_secret_remote_fields_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        discovery.parse_projection(
            CheckResult(name="nginx_dependencies", stdout='{"x":1,"x":2}'),
            host(tmp_path),
            settings(tmp_path),
        )
    value = copy.deepcopy(projection())
    value["servers"][0]["domains"] = ["sk_abcdefghijklmnop.example.test"]
    value["snapshot_digest"] = discovery._digest(
        {k: v for k, v in value.items() if k != "snapshot_digest"}
    )
    with pytest.raises(ValueError):
        parsed(tmp_path, value)


@pytest.mark.parametrize(
    "change", [None, "port_changed", "pin_failed", "helper_timeout", "extra_field"]
)
def test_full_fixed_collection_and_closure_use_only_fresh_safe_bytes(tmp_path, monkeypatch, change):
    calls = []

    class Client:
        def close(self):
            calls.append("closed")

    def connect(_client, _host):
        calls.append("pinned_connect")
        if change == "pin_failed":
            raise ValueError("synthetic wrong fingerprint")

    inventories = 0

    def check(_client, name, command, budget, **kwargs):
        nonlocal inventories
        calls.append(name)
        assert 0 < budget <= 7 and kwargs == {"require_eof": True}
        if name == "os_release":
            text = 'ID=ubuntu\nVERSION_ID="24.04"\n'
        elif name == "platform_tools":
            text = "OPSARK_ARCH=x86_64\n" + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS)
        elif name == "compose_version":
            text = "2.40.1\n"
        elif name == "docker_rootful":
            text = '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}'
        elif name == "compose_inventory":
            inventories += 1
            port = 8082 if change == "port_changed" and inventories == 2 else 8081
            text = json.dumps(
                {
                    "id": "a" * 64,
                    "name": "demo-api-1",
                    "state": "running",
                    "project": "demo",
                    "service": "api",
                    "ports": f"127.0.0.1:{port}->8000/tcp",
                }
            )
        else:
            assert name == "nginx_dependencies" and command == nginx_dependencies_command(
                host(tmp_path)
            )
            if change == "helper_timeout":
                return CheckResult(name=name, status="timeout", exit_code=None)
            value = projection()
            if change == "extra_field":
                value["raw_configuration"] = "synthetic only"
            text = json.dumps(value)
        return CheckResult(name=name, stdout=text)

    monkeypatch.setattr(discovery.paramiko, "SSHClient", Client)
    monkeypatch.setattr(discovery, "_connect_registered", connect)
    monkeypatch.setattr(discovery, "run_check", check)
    result = discovery.run_nginx_dependencies(host(tmp_path), settings(tmp_path))
    assert calls[-1] == "closed"
    assert result.actions_enabled is False and result.loaded_generation == "unknown"
    if change is None:
        assert result.status == "observed" and result.relationships[0].binding == "unique"
        assert inventories == 2
    else:
        assert result.status == "unavailable" and result.relationships == [] and result.files == []
    if change == "port_changed":
        assert result.reason == "evidence_changed"
    if change == "pin_failed":
        assert calls == ["pinned_connect", "closed"]
