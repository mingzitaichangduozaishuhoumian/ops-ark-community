"""Synthetic browser contracts for explicit read-only Compose candidate selection.

No application/backend, SSH, model or credential loader is imported. All browser
resources and API replies are intercepted on an owned loopback origin.
"""

import copy
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-compose-browser-console-token-only"
PRIVATE = "FAKE_RAW_OUTPUT_SECRET_DATABASE_TEXT_DO_NOT_DISPLAY"
CANDIDATE, SNAPSHOT = "a" * 64, "c" * 64


def launch_fixture_browser(playwright):
    engine = os.environ.get("OPSARK_TEST_BROWSER", "chromium")
    if engine not in {"chromium", "firefox", "webkit"}:
        raise ValueError("OPSARK_TEST_BROWSER must be chromium, firefox or webkit")
    return getattr(playwright, engine).launch(headless=True)


def discovered(host="compose-a"):
    return {
        "host_id": host,
        "project": "synthetic-shop",
        "status": "candidates",
        "reason": None,
        "candidates": [
            {
                "candidate_id": CANDIDATE,
                "container_name": "shop-api-1",
                "service_name": "api",
                "state": "running",
                "published_ports": [
                    {
                        "host_ip": "127.0.0.1",
                        "host_port": 18081,
                        "container_port": 8080,
                        "protocol": "tcp",
                    },
                    {
                        "host_ip": "::1",
                        "host_port": 18081,
                        "container_port": 8080,
                        "protocol": "tcp",
                    },
                    {
                        "host_ip": "127.0.0.1",
                        "host_port": 19090,
                        "container_port": 9090,
                        "protocol": "udp",
                    },
                ],
                "service_instances": 1,
                "registration_supported": True,
            },
            {
                "candidate_id": "b" * 64,
                "container_name": "shop-worker-1",
                "service_name": "worker",
                "state": "exited",
                "published_ports": [],
                "service_instances": 1,
                "registration_supported": False,
            },
        ],
        "snapshot_digest": SNAPSHOT,
        "collected_at": "2026-11-06T05:00:00Z",
        "duration_ms": 23,
        "scope": "one_authorized_compose_project",
        "evidence_kind": "observed_compose_labels_and_published_ports",
        "nginx_dependency": "unverified",
        "actions_enabled": False,
    }


class ComposeContract:
    def __init__(
        self,
        *,
        configured=True,
        enabled=True,
        mode="success",
        mutation=None,
        hold=False,
        binding=True,
        preflight=False,
    ):
        self.configured, self.enabled, self.mode, self.mutation, self.hold = (
            configured,
            enabled,
            mode,
            mutation,
            hold,
        )
        self.calls, self.errors, self.pending = [], [], None
        self.binding, self.preflight = binding, preflight
        self.counts = {
            "discovery": 0,
            "preview": 0,
            "onboarding": 0,
            "preflight": 0,
            "forbidden_writes": 0,
            "unexpected_routes": 0,
            "external_requests": 0,
        }
        self.base = ""

    def route(self, route):
        request = route.request
        if not request.url.startswith(self.base + "/"):
            self.counts["external_requests"] += 1
            route.abort()
            return
        path = urlsplit(request.url).path
        if not path.startswith("/api/"):
            filename = "index.html" if path == "/" else path.lstrip("/")
            if filename not in {
                "index.html",
                "app.js",
                "defense.js",
                "nginx-dependencies.js",
                "styles.css",
            }:
                route.abort()
                return
            route.fulfill(
                body=(ROOT / "web" / filename).read_bytes(),
                content_type=(
                    "text/javascript"
                    if filename.endswith(".js")
                    else "text/css"
                    if filename.endswith(".css")
                    else "text/html"
                ),
            )
            return
        body = request.post_data_json if request.post_data else None
        self.calls.append((request.method, path, body))
        if path != "/api/status":
            assert request.headers.get("authorization") == "Bearer " + TOKEN
        status = 200
        if path.endswith("/compose-discovery"):
            assert request.method == "POST" and body == {}
            self.counts["discovery"] += 1
            host = path.split("/")[3]
            value = discovered(host)
            if self.mode == "empty":
                value.update(status="empty", reason="no_label_candidates", candidates=[])
            elif self.mode == "unavailable":
                value.update(
                    status="unavailable",
                    reason="inventory_truncated",
                    candidates=[],
                    snapshot_digest=None,
                )
            elif self.mode == "failure":
                status, value = 503, {"detail": PRIVATE}
            if self.mutation:
                self.mutation(value)
            if self.hold:
                self.pending = (route, value)
                return
        elif path.endswith("/compose-discovery/preview"):
            self.counts["preview"] += 1
            assert request.method == "POST" and body == {
                "candidate_id": CANDIDATE,
                "snapshot_digest": SNAPSHOT,
                "host_port": 18081,
            }
            host = path.split("/")[3]
            value = {
                "host_id": host,
                "candidate_id": CANDIDATE,
                "snapshot_digest": SNAPSHOT,
                "inventory_fragment": (
                    'compose_project = "synthetic-shop"\n'
                    'container_name = "shop-api-1"\n'
                    "container_binding_confirmed = true\n"
                    "expected_upstream_port = 18081\n"
                ),
                "nginx_dependency": "unverified",
                "actions_enabled": False,
            }
            if self.mode == "stale":
                status, value = 409, {"detail": PRIVATE}
            elif self.mode == "unsafe_preview":
                value["inventory_fragment"] += 'api_key = "' + PRIVATE + '"\n'
        elif path == "/api/host-onboarding/prepare":
            self.counts["onboarding"] += 1
            assert request.method == "POST"
            assert type(body) is dict
            value = {
                "host_id": body["host_id"],
                "address": body["address"],
                "port": body["port"],
                "fingerprint": body["expected_fingerprint"],
                "known_hosts": "synthetic-public-pin\n",
                "inventory": '[[hosts]]\nid = "draft"\n'
                + (
                    'compose_project = "' + body["compose_project"] + '"\n'
                    if "compose_project" in body
                    else ""
                )
                + ("container_binding_confirmed = false\n" if "container_name" not in body else ""),
                "key_file": "ssh/synthetic-readonly-reference",
                "known_hosts_file": "ssh/synthetic-public-pin-reference",
                "known_hosts_digests": {
                    "lf": "1" * 64,
                    "crlf": "2" * 64,
                    "no_final_newline": "3" * 64,
                },
            }
        elif path.endswith("/preflight") and self.preflight:
            assert request.method == "POST" and body == {}
            self.counts["preflight"] += 1
            value = {
                "host_id": path.split("/")[3],
                "status": "needs_attention",
                "connection": "ok",
                "platform": "compatible",
                "os_family": "ubuntu",
                "architecture": "x86_64",
                "missing_tools": [],
                "checks": [
                    {
                        "id": "container_state",
                        "status": "unavailable",
                        "reason": "registration_unconfirmed",
                    }
                ],
                "checked_at": "2026-11-06T05:00:00Z",
                "duration_ms": 23,
            }
        else:
            if request.method not in {"GET", "HEAD"}:
                self.counts["forbidden_writes"] += 1
            values = {
                "/api/status": {"version": "synthetic-compose-contract"},
                "/api/capabilities": {
                    "mode": "read_only",
                    "host_onboarding": True,
                    "host_compose_discovery": self.enabled,
                    "host_preflight": self.preflight,
                    "security_observation": False,
                },
                "/api/samples": [],
                "/api/reports": [],
                "/api/hosts": [
                    {
                        "id": name,
                        "name": name,
                        "address": "192.0.2.10",
                        "port": 22,
                        "username": "opsark-readonly",
                        "site_domain": "site.invalid",
                        "container_name": "manual-name",
                        "expected_upstream_port": 8081,
                        "source": "ssh",
                        "health_checks": [],
                        "compose_discovery_configured": self.configured,
                        **(
                            {"container_binding_confirmed": self.binding}
                            if self.binding is not None
                            else {}
                        ),
                    }
                    for name in ("compose-a", "compose-b")
                ],
            }
            if path not in values:
                self.counts["unexpected_routes"] += 1
                route.fulfill(status=404, content_type="application/json", body="{}")
                return
            value = values[path]
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def release(self):
        assert self.pending is not None
        route, value = self.pending
        self.pending = None
        route.fulfill(content_type="application/json", body=json.dumps(copy.deepcopy(value)))
