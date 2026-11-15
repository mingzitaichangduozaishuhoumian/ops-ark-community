"""Platform browser checks for synthetic contracts and a temporary real backend.

Run after installing the chosen Playwright browser into the project environment:
    uv run python tests/browser_platform_smoke.py --browser chromium
The real API uses temporary SQLite storage and a generated in-memory token.
Only local replay investigations run; no real SSH target or model is contacted.
"""

import argparse
import json
import os
import secrets
import socket
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler, build_opener

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-browser-contract-token"
UNTRUSTED_TEXT = '<img src=x onerror="window.platformInjection=true">'


@contextmanager
def static_console():
    assets = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/index.html": ("index.html", "text/html; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/defense.js": ("defense.js", "text/javascript; charset=utf-8"),
        "/nginx-dependencies.js": ("nginx-dependencies.js", "text/javascript; charset=utf-8"),
        "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            asset = assets.get(urlsplit(self.path).path)
            if asset is None:
                self.send_error(404)
                return
            filename, content_type = asset
            data = (ROOT / "web" / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@contextmanager
def real_backend():
    """Import and run the actual app without loading deployment credentials."""
    variables = {
        "OPSARK_DATA_DIR",
        "OPSARK_TOKEN",
        *(name for name in os.environ if name.startswith("OPSARK_")),
    }
    previous = {name: os.environ.get(name) for name in variables}
    with TemporaryDirectory(prefix="opsark-browser-") as directory:
        try:
            for name in variables:
                os.environ.pop(name, None)
            # main's module-level app must also stay inside this temporary directory.
            os.environ["OPSARK_DATA_DIR"] = str(Path(directory) / "bootstrap")
            token = secrets.token_urlsafe(32)
            os.environ["OPSARK_TOKEN"] = token
            sys.path.insert(0, str(ROOT / "src"))
            import uvicorn

            from opsark.config import Settings
            from opsark.main import create_app

            application = create_app(Settings(data_dir=Path(directory) / "active", token=token))
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            server = uvicorn.Server(
                uvicorn.Config(
                    application,
                    host="127.0.0.1",
                    port=port,
                    loop="asyncio",
                    http="h11",
                    ws="none",
                    access_log=False,
                    log_level="error",
                    timeout_graceful_shutdown=3,
                )
            )
            thread = threading.Thread(
                target=server.run, kwargs={"sockets": [listener]}, daemon=True
            )
            thread.start()
            base_url = f"http://127.0.0.1:{port}"
            try:
                opener = build_opener(ProxyHandler({}))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if not thread.is_alive():
                        raise RuntimeError("Temporary backend exited before readiness")
                    if server.started:
                        with opener.open(base_url + "/api/status", timeout=1) as response:
                            if response.status == 200:
                                break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("Temporary backend did not become ready")
                yield base_url, token
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                if thread.is_alive():
                    server.force_exit = True
                    thread.join(timeout=3)
                listener.close()
                if thread.is_alive():
                    raise RuntimeError("Temporary backend did not shut down")
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


def fixture_report(mode):
    report = {
        "id": "platform-contract-fixture",
        "title": "合成平台契约报告",
        "host_id": "fixture-host",
        "host_name": "浏览器合成目标",
        "scenario": "disk",
        "source": "replay",
        "created_at": "2026-10-27T00:00:00Z",
        "status": "inconclusive",
        "summary": "仅验证浏览器显示，不是实际服务器预检。",
        "facts": [],
        "candidates": [],
        "missing": ["合成 API 契约未验证真实平台。"],
        "next_steps": ["核实目标环境。"],
        "verification": [{"name": "恢复验收", "status": "not_run", "detail": "未执行。"}],
        "action": {"executable": False, "reason": "合成契约无执行能力。"},
        "evidence": [
            {
                "id": "E-PLATFORM-PREFLIGHT",
                "check_id": "platform_preflight",
                "target": "fixture-host",
                "source": "replay",
                "collected_at": "2026-10-27T00:00:00Z",
                "status": "ok",
                "output": "Explicit synthetic platform evidence.",
            }
        ],
    }
    if mode != "legacy":
        report["compatibility"] = {
            "status": "compatible" if mode == "compatible" else "unsupported",
            "os_id": "ubuntu" if mode == "compatible" else "alpine",
            "version_id": "24.04" if mode == "compatible" else "synthetic-unverified",
            "architecture": "x86_64",
            "adapter": "ubuntu_debian" if mode == "compatible" else None,
            "available_tools": ["df", "timeout"],
            "missing_tools": ["journalctl"],
            "evidence_ids": ["E-PLATFORM-PREFLIGHT"],
            "detail": "合成预检条件，仅测试显示。" if mode == "compatible" else UNTRUSTED_TEXT,
        }
    return report


def fixture_capabilities(mode):
    capabilities = {"mode": "read_only", "model_configured": False, "ssh_hosts": 0}
    if mode != "legacy":
        capabilities["platforms"] = {
            "controller": {
                "system": "SyntheticOS",
                "architecture": "synthetic64",
                "python": "3.13",
            },
            "managed": {
                "profile": "ubuntu_debian",
                "families": ["ubuntu", "debian"],
                "architectures": ["x86_64", "aarch64"],
                "mode": "read_only",
                "preflight": True,
            },
        }
    if mode == "compatible":
        capabilities["host_preflight"] = True
        capabilities["host_onboarding"] = True
    return capabilities


def check_case(browser, base_url, mode, screenshots):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    failures = []
    page.on("pageerror", lambda error: failures.append(str(error)))
    report = fixture_report(mode)
    preflight_requests = []
    onboarding_requests = []
    trust_digest = "a" * 64
    fixture_host = {
        "id": "fixture-ssh",
        "name": "合成 SSH 主机",
        "source": "ssh",
        "address": "192.0.2.60",
        "port": 22,
        "username": "operator",
        "site_domain": "fixture.invalid",
        "container_name": "fixture-app",
        "trusted_hosts_digest": trust_digest,
    }
    onboarding_draft = {
        "host_id": fixture_host["id"],
        "name": fixture_host["name"],
        "address": fixture_host["address"],
        "port": 22,
        "username": fixture_host["username"],
        "site_domain": fixture_host["site_domain"],
        "container_name": fixture_host["container_name"],
        "expected_upstream_port": 8081,
        "host_key": "ssh-ed25519 " + "A" * 68,
        "expected_fingerprint": "SHA256:" + "A" * 43,
    }

    def route_request(route):
        request = route.request
        url = urlsplit(request.url)
        if not request.url.startswith(base_url + "/"):
            failures.append("Unexpected network destination")
            route.abort()
            return
        path = url.path
        if not path.startswith("/api/"):
            route.continue_()
            return
        if path != "/api/status" and request.headers.get("authorization") != "Bearer " + TOKEN:
            failures.append("Missing synthetic request authentication")
        payloads = {
            "/api/status": {"version": "synthetic-browser-contract", "requires_auth": True},
            "/api/capabilities": fixture_capabilities(mode),
            "/api/samples": [{"id": "fixture", "title": "合成样本", "scenario": "disk"}],
            "/api/hosts": [fixture_host] if mode == "compatible" else [],
            "/api/reports": [report],
            "/api/reports/platform-contract-fixture": report,
            "/api/investigations": report,
        }
        if mode == "compatible" and path == "/api/host-onboarding/prepare":
            onboarding_requests.append((request.method, request.post_data_json))
            payloads[path] = {
                "host_id": fixture_host["id"],
                "address": fixture_host["address"],
                "port": 22,
                "fingerprint": onboarding_draft["expected_fingerprint"],
                "inventory": '[[hosts]]\nid = "fixture-ssh"\n',
                "known_hosts": f"{fixture_host['address']} {onboarding_draft['host_key']}\n",
                "key_file": "ssh/opsark-fixture-ssh-readonly",
                "known_hosts_file": "ssh/opsark-fixture-ssh-known-hosts",
                "known_hosts_digests": {
                    "lf": trust_digest,
                    "crlf": "b" * 64,
                    "no_final_newline": "c" * 64,
                },
            }
        if mode == "compatible" and path == "/api/hosts/fixture-ssh/preflight":
            preflight_requests.append((request.method, request.post_data_json))
            payloads[path] = {
                "host_id": "fixture-ssh",
                "status": "needs_attention",
                "connection": "ok",
                "platform": "compatible",
                "os_family": "ubuntu",
                "architecture": "x86_64",
                "missing_tools": ["df"],
                "checks": [
                    {"id": check, "status": status}
                    for check, status in (
                        ("os_release", "ok"),
                        ("platform_tools", "ok"),
                        ("nginx_status", "inactive"),
                        ("container_state", "permission_denied"),
                        ("disk_bytes", "unavailable"),
                        ("disk_inodes", "unavailable"),
                    )
                ]
                + [
                    {"id": "compose_version", "status": "error", "reason": "unsupported_version"},
                    {"id": "docker_rootful", "status": "error", "reason": "rootless_unsupported"},
                ],
                "checked_at": "2026-10-27T00:00:00Z",
                "duration_ms": 25,
            }
        if path not in payloads:
            failures.append("Unexpected API request: " + path)
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        route.fulfill(content_type="application/json", body=json.dumps(payloads[path]))

    page.route("**/*", route_request)
    try:
        page.goto(base_url, wait_until="networkidle")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#report-id")).to_have_text(report["id"])
        source = page.locator("#source-select")
        source.select_option("ssh")
        expect(page.locator("#open-host-onboarding")).to_be_hidden()
        if mode == "compatible":
            expect(page.locator("#run-investigation")).to_be_enabled()
        else:
            expect(page.locator("#run-investigation")).to_be_disabled()
            expect(page.locator("#selection-note")).to_contain_text("服务端 TOML")
        source.select_option("replay")
        page.locator("#tab-boundary").click()
        section = page.locator("#compatibility-section")
        expect(section).to_be_visible()
        if mode == "legacy":
            expect(section).to_contain_text("环境预检未知")
            expect(section).to_contain_text("旧报告未包含环境预检")
            expect(section).to_contain_text("工具可用性未知")
        else:
            expect(section).to_contain_text(
                "符合当前适配条件" if mode == "compatible" else "目标环境不支持"
            )
            expect(section).to_contain_text("工具缺口：journalctl")
            expect(section).to_contain_text("此预检来自合成样本")
            if mode == "unsupported":
                expect(section).to_contain_text(UNTRUSTED_TEXT)
                expect(section.locator("img")).to_have_count(0)
                assert page.evaluate("window.platformInjection === undefined")
            section.get_by_role("button", name="E-PLATFORM-PREFLIGHT ↗").click()
            expect(
                page.locator('details[data-evidence-id="E-PLATFORM-PREFLIGHT"]')
            ).to_have_attribute("open", "")
            page.locator("#tab-boundary").click()
        for width in (1440, 768, 390, 320):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (
                mode,
                width,
                "Horizontal page overflow",
            )
            if screenshots and mode == "compatible" and width in (1440, 320):
                page.screenshot(path=str(screenshots / f"platform-{width}.png"), full_page=True)
        page.locator('button[data-view="capabilities"]').click()
        details = page.locator("#capability-details")
        expect(details).to_contain_text("控制台运行平台与被管理服务器的适配范围分别验证")
        if mode == "legacy":
            expect(details).to_contain_text("旧实例未提供平台信息")
            expect(details).to_contain_text("旧实例未提供适配范围")
        else:
            expect(details).to_contain_text("SyntheticOS / synthetic64")
            expect(details).to_contain_text("ubuntu / debian")
            expect(details).to_contain_text("x86_64 / aarch64")
        if mode == "compatible":
            page.locator('button[data-view="hosts"]').click()
            assert not preflight_requests and not onboarding_requests
            page.locator("#host-onboarding > summary").click()
            for name, value in onboarding_draft.items():
                page.locator(f'#host-onboarding-form [name="{name}"]').fill(str(value))
            page.locator("#host-onboarding-confirm").check()
            page.locator("#host-onboarding-prepare").click()
            expect(page.locator("#host-onboarding-result")).to_be_visible()
            expect(page.locator("#host-onboarding-inventory")).to_have_value(
                '[[hosts]]\nid = "fixture-ssh"\n'
            )
            assert onboarding_requests == [("POST", onboarding_draft)]
            page.locator("#host-onboarding-preflight").click()
            card = page.locator('.host-card[data-host-id="fixture-ssh"]')
            preflight = card.get_by_role("button", name="运行接入预检")
            expect(preflight).to_be_focused()
            assert not preflight_requests
            preflight.click()
            result = card.locator("[data-host-preflight-result]")
            expect(result).to_have_attribute("data-status", "needs_attention")
            expect(result.locator('[data-check-id="container_state"]')).to_contain_text("权限不足")
            expect(result).to_contain_text("df")
            expect(result.locator('[data-check-id="compose_version"]')).to_contain_text(
                "插件版本不在 Compose v2 范围"
            )
            expect(result.locator('[data-check-id="docker_rootful"]')).to_contain_text(
                "检测到 rootless"
            )
            assert preflight_requests == [("POST", {})]
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert not failures, failures
    finally:
        context.close()


def check_handoff_recheck(browser, base_url, enabled):
    context = browser.new_context(viewport={"width": 390, "height": 860}, accept_downloads=True)
    page = context.new_page()
    errors, recheck_requests, downloads, exports = [], [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("download", lambda download: downloads.append(download))
    report = fixture_report("compatible") | {"source": "ssh", "scope_hash": "b" * 64}
    report["evidence"][0]["output"] = UNTRUSTED_TEXT
    report_path = f"/api/reports/{report['id']}"
    job = "a" * 32
    historical_job = "c" * 32
    older = [
        {
            "id": "pending-fixture",
            "at": "2026-10-27T00:03:00Z",
            "status": "pending",
            "matched_checks": 2,
            "configured_checks": 3,
        },
        {
            "id": "failed-fixture",
            "at": "2026-10-27T00:02:00Z",
            "status": "failed",
            "matched_checks": 1,
            "configured_checks": 3,
        },
    ]
    new = {
        "id": "restored-fixture",
        "at": "2026-10-27T00:04:00Z",
        "status": "passed",
        "matched_checks": 3,
        "configured_checks": 3,
    }
    history = older.copy()
    capabilities = fixture_capabilities("compatible") | {"handoff_timeline": True}
    if enabled:
        capabilities["handoff_recheck"] = True

    def route_request(route):
        request = route.request
        url = urlsplit(request.url)
        if not request.url.startswith(base_url + "/"):
            errors.append("Unexpected network destination")
            route.abort()
            return
        if not url.path.startswith("/api/"):
            route.continue_()
            return
        if url.path != "/api/status" and request.headers.get("authorization") != "Bearer " + TOKEN:
            errors.append("Missing synthetic request authentication")
        status = 200
        payloads = {
            "/api/status": {"version": "synthetic-handoff-contract", "requires_auth": True},
            "/api/capabilities": capabilities,
            "/api/samples": [],
            "/api/hosts": [],
            "/api/reports": [report],
            report_path: report,
            report_path + "/handoff-options": {
                "jobs": [
                    {"id": job_id, "status": "verified", "at": "2026-10-27T00:01:00Z"}
                    for job_id in (job, historical_job)
                ],
                "rechecks": [{"id": row["id"], "at": row["at"]} for row in older],
            },
        }
        query = parse_qs(url.query)
        if enabled and url.path == report_path + "/handoff-rechecks":
            body = request.post_data_json if request.method == "POST" else None
            recheck_requests.append((request.method, query, body))
            if request.method == "GET" and query == {"job_id": [job]}:
                payloads[url.path] = {"can_run": True, "rechecks": history}
            elif request.method == "GET" and query == {"job_id": [historical_job]}:
                payloads[url.path] = {"can_run": False, "rechecks": older}
            elif request.method == "POST" and not query and body == {"job_id": job}:
                history.insert(0, new)
                payloads[url.path] = new
                status = 201
        if url.path == report_path + "/handoff" and request.method == "GET":
            exports.append(query)
            route.fulfill(content_type="text/markdown", body="# 客户交接摘要\n")
            return
        if (request.method != "GET" and status != 201) or url.path not in payloads:
            errors.append(f"Unexpected API request: {request.method} {url.path}")
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        route.fulfill(
            status=status, content_type="application/json", body=json.dumps(payloads[url.path])
        )

    page.route("**/*", route_request)
    try:
        page.goto(base_url, wait_until="networkidle")
        page.locator("#token-input").fill(TOKEN)
        page.locator("#login-button").click()
        expect(page.locator("#report-id")).to_have_text(report["id"])
        page.locator("#export-handoff").click()
        expect(page.locator("#handoff-dialog")).to_be_visible()
        run = page.locator("#handoff-run-recheck")
        choose = page.locator("#handoff-recheck")
        choose_job = page.locator("#handoff-job")
        expect(choose_job).to_be_enabled()
        assert not recheck_requests and not exports
        if enabled:
            choose_job.select_option(historical_job)
            expect(choose).to_be_enabled()
            expect(run).to_be_disabled()
            expect(page.locator("#handoff-run-recheck-note")).to_contain_text("暂不能发起复验")
            choose.select_option(older[1]["id"])
            expect(page.locator("#handoff-recheck-result")).to_contain_text("复验未通过")
        choose_job.select_option(job)
        expect(choose).to_be_enabled()
        expect(choose).to_have_value("")
        if enabled:
            expect(run).to_be_enabled()
            assert recheck_requests == [
                ("GET", {"job_id": [historical_job]}, None),
                ("GET", {"job_id": [job]}, None),
            ]
            result = page.locator("#handoff-recheck-result")
            for row, label in zip(older, ("待验收", "复验未通过"), strict=True):
                choose.select_option(row["id"])
                expect(result).to_contain_text(label)
                expect(result).to_contain_text(f"{row['matched_checks']}/3")
            run.click()
            expect(choose).to_have_value(new["id"])
            expect(result).to_contain_text("登记业务复验通过")
            expect(result).to_contain_text("3/3")
            assert not exports and not downloads
            assert [entry for entry in recheck_requests if entry[0] == "POST"] == [
                ("POST", {}, {"job_id": job})
            ]
            expect(page.locator("#handoff-dialog")).not_to_contain_text(UNTRUSTED_TEXT)
            choose.select_option(older[0]["id"])
            expect(result).to_contain_text("待验收")
        else:
            expect(run).to_be_hidden()
            assert not recheck_requests
        choose.select_option(older[1]["id"])
        if enabled:
            expect(page.locator("#handoff-recheck-result")).to_contain_text("复验未通过")
        with page.expect_download() as saved:
            page.locator("#handoff-download").click()
        assert saved.value.suggested_filename == "opsark-handoff.md"
        assert Path(saved.value.path()).read_text(encoding="utf-8") == "# 客户交接摘要\n"
        assert exports == [{"job_id": [job], "recheck_report_id": [older[1]["id"]]}]
        assert not errors, errors
    finally:
        context.close()


def check_real_backend(browser, screenshots):
    with real_backend() as (base_url, token):
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000}, accept_downloads=True
        )
        page = context.new_page()
        failures = []
        page.on("pageerror", lambda error: failures.append(str(error)))

        def guard_request(route):
            request = route.request
            if not request.url.startswith(base_url + "/"):
                failures.append("Unexpected network destination from the real console")
                route.abort()
                return
            path = urlsplit(request.url).path
            allowed_replay = (
                request.method == "POST"
                and path == "/api/investigations"
                and request.post_data_json
                == {
                    "source": "replay",
                    "scenario": "disk",
                    "sample_id": "disk-healthy",
                }
            )
            allowed_mode = (
                request.method == "PUT"
                and path == "/api/automation"
                and request.post_data_json
                in [
                    {"mode": "assisted", "expected_revision": 0},
                    {"mode": "automatic", "expected_revision": 1},
                    {"mode": "manual", "expected_revision": 2},
                ]
            )
            if request.method not in {"GET", "HEAD"} and not (allowed_replay or allowed_mode):
                failures.append("Unexpected mutation from the real console")
                route.abort()
                return
            route.continue_()

        page.route("**/*", guard_request)
        try:
            page.goto(base_url, wait_until="networkidle")
            page.locator("#token-input").fill(token)
            with page.expect_response(
                lambda response: urlsplit(response.url).path == "/api/capabilities"
            ) as received_capabilities:
                page.locator("#login-button").click()
            capabilities = received_capabilities.value.json()
            assert capabilities["model_configured"] is False
            assert capabilities["ssh_hosts"] == 0
            assert capabilities["automation_modes"] is True
            assert capabilities["host_onboarding"] is True
            expect(page.locator("#workspace-heading")).to_be_focused()
            source = page.locator("#source-select")
            onboarding = page.locator("#open-host-onboarding")
            expect(onboarding).to_be_hidden()
            source.select_option("ssh")
            expect(onboarding).to_be_visible()
            expect(page.locator("#run-investigation")).to_be_disabled()
            expect(page.locator("#selection-note")).to_contain_text("核对主机指纹")
            source.select_option("replay")
            expect(onboarding).to_be_hidden()
            source.select_option("ssh")
            await_onboarding = page.locator("#scenario-select")
            await_onboarding.focus()
            page.keyboard.press("Tab")
            expect(onboarding).to_be_focused()
            page.keyboard.press("Enter")
            wizard = page.locator("#host-onboarding")
            expect(page.locator('button[data-view="hosts"]')).to_have_attribute(
                "aria-current", "page"
            )
            expect(wizard).to_have_attribute("open", "")
            expect(wizard.locator("summary")).to_be_focused()
            expect(wizard.locator('[name="host_id"]')).to_be_visible()
            page.locator('button[data-view="workspace"]').click()
            source.select_option("replay")
            expect(onboarding).to_be_hidden()
            expect(page.locator("#automation-mode-section")).to_be_visible()
            expect(page.locator("#automation-current")).to_contain_text("手动模式")
            boundary = page.locator("#automation-execution-boundary")
            expect(boundary).to_contain_text("当前执行器尚未配置")
            expect(boundary).to_contain_text("保存模式不会新增授权或恢复暂停任务")
            for mode in ("assisted", "automatic", "manual"):
                page.locator("#automation-mode-select").select_option(mode)
                with page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == "/api/automation"
                        and response.request.method == "PUT"
                    )
                ) as saved_mode:
                    page.locator("#save-automation-mode").click()
                assert saved_mode.value.status == 200
                assert saved_mode.value.json()["mode"] == mode
                assert saved_mode.value.json()["execution_available"] is False
                assert saved_mode.value.json()["supported_execution_modes"] == []
                assert saved_mode.value.json()["policy"]["automatic"] is None
                expect(page.locator("#save-automation-mode")).to_be_disabled()
            for width in (1440, 768, 390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"), width
            page.set_viewport_size({"width": 1440, "height": 1000})
            expect(page.locator("#app-shell")).to_be_visible()
            page.locator("#sample-select").select_option("disk-healthy")
            with page.expect_response(
                lambda response: (
                    urlsplit(response.url).path == "/api/investigations"
                    and response.request.method == "POST"
                )
            ) as received_report:
                page.locator("#run-investigation").click()
            assert received_report.value.status == 200
            report = received_report.value.json()
            assert report["source"] == "replay"
            assert report["action"]["executable"] is False
            assert report["compatibility"]["status"] == "unknown"
            expect(page.locator("#report-id")).to_have_text(report["id"])
            # Rendering the report precedes the final history refresh. Wait for
            # that workflow to settle before clicking a tab whose position can move.
            expect(page.locator("#run-investigation")).to_be_enabled()
            page.locator("#tab-boundary").click()
            expect(page.locator("#compatibility-section")).to_contain_text("环境预检未知")
            expect(page.locator("#compatibility-section")).to_contain_text("此预检来自合成样本")
            page.locator('button[data-view="capabilities"]').click()
            controller = capabilities["platforms"]["controller"]
            expect(page.locator("#capability-details")).to_contain_text(
                controller["system"] + " / " + controller["architecture"]
            )
            expect(page.locator("#capability-details")).to_contain_text(controller["python"])
            page.locator('button[data-view="workspace"]').click()
            page.locator("#tab-evidence").click()
            expect(page.locator('details[data-evidence-id="E-OS-RELEASE"]')).to_be_visible()
            with page.expect_download() as received_download:
                page.locator("#export-report").click()
            download = received_download.value
            assert download.suggested_filename == "opsark-" + report["id"] + ".md"
            content = Path(download.path()).read_text(encoding="utf-8")
            assert "## 目标环境适配" in content
            assert "状态：unknown" in content
            assert "回放样本：证据为预置虚构数据" in content
            assert token not in content

            internal_markers = (report["host_name"], "/dev/vda1", "/srv/site-data")
            assert all(marker in content for marker in internal_markers)
            handoff_path = f"/api/reports/{report['id']}/handoff"
            with (
                page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == handoff_path
                        and response.request.method == "GET"
                    )
                ) as handoff_response,
                page.expect_download() as handoff_download,
            ):
                page.locator("#export-handoff").click()
            assert handoff_response.value.status == 200
            attachment = handoff_response.value.headers.get("content-disposition", "")
            assert attachment.startswith("attachment;") and "opsark-handoff.md" in attachment
            assert handoff_download.value.suggested_filename == "opsark-handoff.md"
            handoff = Path(handoff_download.value.path()).read_text(encoding="utf-8")
            assert "客户交接摘要" in handoff
            assert "回放样本为合成数据，仅用于演练。" in handoff and "待验收" in handoff
            assert all(marker not in handoff for marker in (*internal_markers, token))

            expect(page.locator("#investigation-form")).not_to_have_attribute("aria-busy", "true")
            page.locator("#refresh-reports").click()
            expect(page.locator("#refresh-reports")).to_be_enabled()
            history = page.locator(f'button[data-report-id="{report["id"]}"]')
            expect(history).to_have_count(1)
            with page.expect_response(
                lambda response: urlsplit(response.url).path == "/api/reports/" + report["id"]
            ) as reopened_report:
                history.focus()
                page.keyboard.press("Enter")
            assert reopened_report.value.json()["id"] == report["id"]
            expect(page.locator("#report-id")).to_have_text(report["id"])
            expect(history).to_be_focused()
            if screenshots:
                page.locator("#tab-boundary").click()
                page.screenshot(path=str(screenshots / "platform-real-api.png"), full_page=True)
            page.locator("#logout-button").click()
            expect(page.locator("#login-screen")).to_be_visible()
            expect(page.locator("#token-input")).to_have_value("")
            assert not failures, failures
        finally:
            context.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), default="chromium")
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument(
        "--contracts-only", action="store_true", help="Skip the temporary actual API integration"
    )
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with static_console() as base_url, sync_playwright() as playwright:
        browser = getattr(playwright, args.browser).launch(headless=True)
        try:
            for mode in ("compatible", "unsupported", "legacy"):
                check_case(browser, base_url, mode, args.screenshots)
            for enabled in (True, False):
                check_handoff_recheck(browser, base_url, enabled)
            if not args.contracts_only:
                check_real_backend(browser, args.screenshots)
            print(
                json.dumps(
                    {
                        "browser": args.browser,
                        "version": browser.version,
                        "synthetic_contract_cases": 5,
                        "viewport_widths": [1440, 768, 390, 320],
                        "real_backend_replay_verified": not args.contracts_only,
                        "real_backend_mode_selection_verified": not args.contracts_only,
                        "real_backend_customer_handoff_verified": not args.contracts_only,
                        "real_backend_keyboard_onboarding_verified": not args.contracts_only,
                        "remote_target_or_model_verified": False,
                    }
                )
            )
        finally:
            browser.close()


if __name__ == "__main__":
    run()
