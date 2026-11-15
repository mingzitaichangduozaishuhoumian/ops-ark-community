"""Real console/API/Paramiko/Root Web approval, using an isolated network=none guest.

The existing synthetic parent/vendor prerequisites remain explicit. No browser
route interception, invoker replacement, fake RPC response or runtime controller
monkeypatch is used.
"""

import copy
import hashlib
import json
import os
import queue
import secrets
import shutil
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from activation_guest_acceptance import ROOT, docker, inspect_owned
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

from opsark.automatic_store import AutomaticStore, digest
from opsark.config import Settings, load_hosts, load_patch_targets
from opsark.patch_api import PatchService
from opsark.patch_client import invoke
from opsark.patch_store import PatchStore

HOST = "debian-activation-lab"
JOB = "a" * 32
PREFIX = "/api/service-activations"


def check(value, detail):
    if not value:
        raise RuntimeError(detail)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def probe(identifier):
    return json.loads(
        docker(
            [
                "exec",
                identifier,
                "/usr/bin/python3",
                "-I",
                "/opt/opsark-activation-lab/web_probe.py",
            ],
            timeout=40,
        )
    )


@contextmanager
def ssh_relay(identifier):
    """Carry encrypted SSH bytes only; the production client still authenticates sshd."""
    executable = shutil.which("docker")
    check(executable is not None, "Docker CLI missing")
    endpoint = (
        "npipe:////./pipe/dockerDesktopLinuxEngine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    argv = [
        executable,
        "--host",
        endpoint,
        "exec",
        "-i",
        "--user",
        "opsark-repair",
        identifier,
        "/usr/bin/python3",
        "-I",
        "/usr/local/libexec/opsark-activation-lab-relay.py",
    ]
    environment = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_")}

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with subprocess.Popen(  # noqa: S603 -- one owned guest, fixed unprivileged byte relay.
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        bufsize=0,
    ) as child:
        header = struct.Struct("!cII")
        channels, send_lock, map_lock = {}, threading.Lock(), threading.Lock()
        ready = threading.Event()

        def read_exact(length):
            data = bytearray()
            while len(data) < length:
                chunk = child.stdout.read(length - len(data))
                if not chunk:
                    raise EOFError("Guest byte relay closed")
                data.extend(chunk)
            return bytes(data)

        def send(kind, identifier, data=b""):
            with send_lock:
                view = memoryview(header.pack(kind, identifier, len(data)) + data)
                while view:
                    view = view[child.stdin.write(view) :]

        def receive():
            try:
                check(read_exact(6) == b"READY\n", "Guest relay handshake failed")
                ready.set()
                while True:
                    kind, identifier, length = header.unpack(read_exact(header.size))
                    check(kind in {b"D", b"C"} and length <= 65536, "Invalid guest relay frame")
                    data = read_exact(length)
                    with map_lock:
                        channel = channels.get(identifier)
                    if channel is not None:
                        channel.put(data if kind == b"D" else None, timeout=5)
            except (OSError, ValueError, RuntimeError, EOFError, queue.Full):
                pass
            finally:
                with map_lock:
                    waiting = list(channels.values())
                for channel in waiting:
                    with suppress(queue.Full):
                        channel.put_nowait(None)

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        next_id = 0

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                nonlocal next_id
                self.request.settimeout(90)
                channel = queue.Queue(maxsize=128)
                with map_lock:
                    next_id += 1
                    identifier = next_id
                    channels[identifier] = channel

                def inbound():
                    try:
                        while data := self.request.recv(65536):
                            send(b"D", identifier, data)
                    except (OSError, ValueError):
                        pass
                    finally:
                        with suppress(OSError, ValueError):
                            send(b"E", identifier)

                try:
                    send(b"O", identifier)
                    pump = threading.Thread(target=inbound, daemon=True)
                    pump.start()
                    while data := channel.get(timeout=90):
                        self.request.sendall(data)
                except (OSError, ValueError, queue.Empty):
                    pass
                finally:
                    with map_lock:
                        channels.pop(identifier, None)
                    with suppress(OSError, ValueError):
                        send(b"C", identifier)
                    with suppress(OSError):
                        self.request.shutdown(socket.SHUT_RDWR)

        try:
            check(ready.wait(30), "Guest byte relay did not become ready")
            with Server(("127.0.0.1", 0), Handler) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    yield server.server_address[1]
                finally:
                    server.shutdown()
                    thread.join(timeout=3)
        finally:
            child.stdin.close()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
            reader.join(timeout=2)


def configure(directory, identifier, port, before, *, activation_rescan=False):
    key = directory / "repair.key"
    docker(["cp", identifier + ":/opt/opsark-activation-lab/client", str(key)])
    key.chmod(0o600)
    readonly = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    (directory / "readonly.key").write_bytes(readonly)
    (directory / "readonly.key").chmod(0o600)
    public = docker(["exec", identifier, "/usr/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
    (directory / "known_hosts").write_text(
        f"[127.0.0.1]:{port} " + " ".join(public.split()[:2]) + "\n", encoding="utf-8"
    )
    (directory / "inventory.toml").write_text(
        '[credentials.lab]\nkey_file="readonly.key"\nknown_hosts_file="known_hosts"\n'
        '[[hosts]]\nid="debian-activation-lab"\nname="Debian isolated Web activation"\n'
        'address="127.0.0.1"\nusername="opsark-readonly"\ncredential="lab"\n'
        f'port={port}\nsite_domain="localhost"\n',
        encoding="utf-8",
    )
    save(
        directory / "patch.json",
        {
            "schema_version": 1,
            "targets": {HOST: {"key_file": str(key), "policy_digest": digest(before["policy"])}},
        },
    )
    save(
        directory / "policy.json",
        {
            "enabled": True,
            "host_ids": [HOST],
            "allowed_actions": ["os_security_upgrade"],
            "allowed_packages": ["zlib1g"],
            "max_packages_per_job": 1,
            "allow_service_restart": True,
            "allow_reboot": False,
            "service_activation": {
                "enabled": True,
                "host_ids": [HOST],
                "allowed_packages": ["zlib1g"],
                "allowed_units": ["activation-fixture.service"],
                "max_services_per_activation": 1,
            },
        },
    )
    data = directory / "data"
    store = PatchStore(data / "patches.sqlite3")
    store.save_plan(HOST, before["plan"])
    store.save_job(HOST, before["job"])
    settings = Settings(
        data_dir=data,
        token=secrets.token_urlsafe(32),
        inventory_path=directory / "inventory.toml",
        patch_inventory_path=directory / "patch.json",
        vulnerability_scan_enabled=activation_rescan,
        vulnerability_scan_host_ids=(HOST,) if activation_rescan else (),
        vulnerability_scan_interval_seconds=3600,
    )
    target = load_patch_targets(settings, load_hosts(settings))[HOST]
    safety = invoke(
        target,
        {"schema_version": 1, "op": "automatic_status", "policy_digest": target.policy_digest},
    )
    automatic = AutomaticStore(data / "automatic.sqlite3")
    automatic.record_remote_safety(
        HOST, PatchService._automatic_scope(target), target.policy_digest, safety
    )
    check(automatic.latch(HOST)["remote_safety"] == before["safety"], "Pause import changed")
    return settings


def retained(settings):
    """Hash the original SQL rows only, excluding unrelated monitor leases and new activations."""
    result = {}
    for filename, queries in {
        "patches.sqlite3": {
            "job": "SELECT payload FROM patch_jobs",
            "plan": "SELECT payload FROM patch_plans",
        },
        "automatic.sqlite3": {
            "latch": "SELECT payload,active FROM automatic_latches",
            "remote": "SELECT payload FROM automatic_remote_states",
        },
    }.items():
        with closing(sqlite3.connect(settings.data_dir / filename)) as connection:
            for name, query in queries.items():
                result[name] = digest(connection.execute(query).fetchall())
    return result


class Controller:
    def __init__(self, settings, directory):
        self.settings, self.directory, self.process = settings, directory, None
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.headers = {"Authorization": "Bearer " + settings.token}
        self.client = httpx.Client(
            base_url=self.base, headers=self.headers, trust_env=False, timeout=90
        )
        self.log = (directory / "controller.log").open("ab")
        self.pids = []

    def start(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("OPSARK_")}
        environment.update(
            PYTHONPATH=str(ROOT / "src"),
            PYTHONUNBUFFERED="1",
            OPSARK_DATA_DIR=str(self.settings.data_dir),
            OPSARK_TOKEN=self.settings.token,
            OPSARK_INVENTORY=str(self.settings.inventory_path),
            OPSARK_PATCH_INVENTORY=str(self.settings.patch_inventory_path),
            OPSARK_AUTOMATION_POLICY=str(self.directory / "policy.json"),
        )
        if self.settings.vulnerability_scan_enabled:
            environment.update(
                OPSARK_VULNERABILITY_SCAN_ENABLED="true",
                OPSARK_VULNERABILITY_SCAN_HOSTS=HOST,
                OPSARK_VULNERABILITY_SCAN_INTERVAL="3600",
            )
        self.process = subprocess.Popen(  # noqa: S603 -- actual production app, private config only.
            [
                sys.executable,
                "-m",
                "uvicorn",
                "opsark.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--workers",
                "1",
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=self.log,
        )
        self.pids.append(self.process.pid)
        # Windows termination leaves bounded monitor leases to expire naturally.
        # Never clear a lease or ledger to make the restarted controller pass.
        for _ in range(450):
            check(self.process.poll() is None, "Controller stopped; inspect controller.log")
            try:
                response = self.client.get("/api/automation")
                if response.status_code == 200 and response.json()["mode_sync_complete"]:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.2)
        raise RuntimeError("Controller mode did not synchronize over real SSH")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=15)

    def close(self):
        self.stop()
        self.client.close()
        self.log.close()


def login(page, controller):
    page.goto(controller.base, wait_until="networkidle")
    page.locator("#token-input").fill(controller.settings.token)
    page.locator("#login-button").click()
    expect(page.locator("#app-shell")).to_be_visible()
    page.locator("#remediation-nav").click()
    expect(page.locator("[data-service-activation-prepare]")).to_be_enabled(timeout=30000)


def modes(page, controller, mode):
    page.locator("#automation-mode-select").select_option(mode)
    with page.expect_response(
        lambda r: urlsplit(r.url).path == "/api/automation" and r.request.method == "PUT"
    ) as response:
        page.locator("#save-automation-mode").click()
    check(
        response.value.status == 200 and response.value.json()["mode"] == mode,
        "Web mode change failed",
    )
    expect(page.locator("[data-service-activation-prepare]")).to_be_enabled()
    return controller.client.get("/api/automation").json()["revision"]


def preview(page):
    with page.expect_response(lambda r: urlsplit(r.url).path == PREFIX + "/plans") as response:
        page.locator("[data-service-activation-prepare]").click()
    check(response.value.status == 200, "Real preview failed: " + response.value.text())
    expect(page.locator("#service-activation-dialog")).to_be_visible()
    return response.value.json()


def check_rescan(controller, page, identifier, output, plan, checks):
    endpoint = PREFIX + f"/{HOST}/{plan['activation_id']}/evidence"
    for _ in range(100):
        pending = controller.client.get(endpoint).json()
        if pending.get("rescan_request") is not None:
            break
        page.wait_for_timeout(100)
    else:
        raise RuntimeError("Verified activation did not enqueue an independent rescan")
    request = pending["rescan_request"]
    check(
        request["status"] in {"pending", "claimed"} and pending["evidence_status"] == "incomplete",
        "Pending scan was reported complete",
    )
    with page.expect_download() as download:
        page.locator("#service-activation-detail").get_by_role(
            "button", name="导出激活证据"
        ).click()
    download.value.save_as(str(output / "web-evidence-pending.json"))
    checks["pending_rescan_export_is_incomplete"] = True
    docker(
        [
            "exec",
            identifier,
            "/usr/bin/python3",
            "-I",
            "/opt/opsark-activation-lab/fixture.py",
            "rescan-release",
        ]
    )
    for _ in range(150):
        bundle = controller.client.get(endpoint).json()
        if bundle.get("evidence_status") == "internally_consistent":
            break
        page.wait_for_timeout(200)
    else:
        raise RuntimeError("Independent rescan/export did not complete")
    request = bundle["rescan_request"]
    check(
        request["event_kind"] == "service_activation"
        and request["job_id"] is None
        and request["original_job_id"] == JOB
        and request["activation_id"] == request["event_key"] == plan["activation_id"],
        "Rescan was associated with the original installation instead of this activation",
    )
    check(
        request["status"] == "complete" and request["attempt_count"] == 1,
        "Rescan was replayed or remained incomplete",
    )
    observations = bundle["observations"]
    check(len(observations) == 1, "Unexpected independent observation count")
    observed = observations[0]
    check(
        observed["id"] == request["result_observation_id"]
        and observed["scan_id"] == request["result_scan_id"],
        "Scan/observation ID mismatch",
    )
    collection = observed["collection_evidence"]
    facts = collection["facts"]
    check(
        collection["collection_kind"] == "native_probe"
        and collection["assessment_kind"] == "not_evaluated"
        and collection["facts_digest"] == digest(facts),
        "Evidence provenance was promoted",
    )
    check(
        facts["runtime"]["status"] == "complete"
        and facts["runtime"]["outdated_process_count"] == 0
        and facts["health"]["passed"]
        and facts["package"]["installed_version"] == plan["plan"]["candidate_version"],
        "Rescan native facts did not confirm the current runtime/package/HTTP",
    )
    check(
        observed["status"] == "partial"
        and observed["findings"] == []
        and observed["source_receipts"] == [],
        "Native scan invented official vendor findings",
    )
    persisted = controller.client.get("/api/vulnerability-watch/observations/" + observed["id"])
    check(
        persisted.status_code == 200 and persisted.json() == observed,
        "Export did not retain the independently persisted observation",
    )
    events = controller.client.get("/api/vulnerability-watch/alerts").json()
    check(
        all(event["kind"] == "scan_coverage" for event in events),
        "Native-only observation invented a vendor vulnerability or recovery event",
    )
    check(
        bundle["evidence_provenance"]["original_patch"] == "synthetic_fixture",
        "Synthetic parent provenance was lost",
    )
    checks["independent_rescan_identity_and_native_facts"] = True
    checks["synthetic_parent_and_unassessed_vendor_are_explicit"] = True
    save(output / "rescan-bundle-before-latest.json", bundle)
    latest = controller.client.post("/api/remediation/scans", json={"host_id": HOST})
    check(
        latest.status_code == 200 and latest.json()["scan_id"] != request["result_scan_id"],
        "Control read did not replace the latest scan",
    )
    repeated = controller.client.get(endpoint).json()
    check(
        repeated["rescan_request"] == request and repeated["observations"] == observations,
        "Export substituted the latest scan for the original rescan",
    )
    checks["new_latest_scan_does_not_replace_rescan_evidence"] = True
    page.locator("#service-activation-detail").get_by_role("button", name="查询原激活记录").click()
    expect(page.locator("#service-activation-detail")).to_contain_text("独立复扫 ID")
    expect(page.locator("#service-activation-detail")).to_contain_text("合成前置件")
    checks["web_distinguishes_synthetic_parent_and_rescan_reference"] = True
    scan_calls = [r for r in probe(identifier)["rpc"] if r["request"]["op"] == "scan"]
    return {
        "rescan_request": request,
        "observation_id": observed["id"],
        "rescan_scan_id": observed["scan_id"],
        "later_scan_id": latest.json()["scan_id"],
        "assessment_kind": collection["assessment_kind"],
        "scan_rpc_count_before_restart": len(scan_calls),
    }


def run_browser(controller, identifier, output, browser_name, before, *, activation_rescan=False):
    checks, requests, failures, responses = {}, [], [], []
    with sync_playwright() as playwright:
        browser = getattr(playwright, browser_name).launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1100}, accept_downloads=True
        )
        page = context.new_page()
        page.on("pageerror", lambda error: failures.append(str(error)))

        def audit(request):
            path = urlsplit(request.url).path
            if path.startswith(PREFIX) or path == "/api/automation":
                requests.append(
                    {
                        "method": request.method,
                        "path": path,
                        "body": request.post_data_json
                        if request.method in {"POST", "PUT"}
                        else None,
                    }
                )

        page.on("request", audit)

        def audit_response(response):
            path = urlsplit(response.url).path
            if path.startswith(PREFIX) and not path.endswith("/evidence"):
                try:
                    body = response.json()
                except PlaywrightError:
                    # Navigation/relogin can discard an in-flight read body.
                    # Record that gap; never replace it with an invented response.
                    body = {"body_unavailable_after_navigation": True}
                responses.append(
                    {
                        "path": path,
                        "status": response.status,
                        "host_received_at": datetime.now(UTC).isoformat(),
                        "body": body,
                    }
                )

        page.on("response", audit_response)
        try:
            unauthenticated = httpx.get(controller.base + PREFIX, trust_env=False)
            check(unauthenticated.status_code == 401, "Unauthenticated activation read admitted")
            checks["real_api_authentication"] = True
            login(page, controller)
            check(
                controller.client.get("/api/automation").json()["mode"] == "manual",
                "Initial mode was not manual",
            )
            manual = preview(page)
            expect(page.locator("#service-activation-confirm")).to_be_disabled()
            expect(page.locator("#service-activation-execute")).to_be_disabled()
            page.locator("#service-activation-cancel").click()
            checks["manual_preview_cannot_approve"] = True
            revision = modes(page, controller, "assisted")
            canceled = preview(page)
            expect(page.locator("#service-activation-confirm")).not_to_be_checked()
            expect(page.locator("#service-activation-execute")).to_be_disabled()
            page.locator("#service-activation-confirm").check()
            expect(page.locator("#service-activation-execute")).to_be_enabled()
            page.locator("#service-activation-cancel").click()
            unchanged = probe(identifier)
            check(
                unchanged["pid"] == before["pid"] and unchanged["restart_intents"] == 0,
                "Preview/cancellation restarted the service",
            )
            checks["unchecked_and_cancel_do_not_submit"] = True
            plan = preview(page)
            body = {
                "host_id": HOST,
                "activation_id": plan["activation_id"],
                "expected_activation_digest": plan["activation_digest"],
                "expected_mode_revision": revision,
                "confirm_activate": True,
            }
            for name, change, expected in (
                ("missing_confirmation_rejected", {"confirm_activate": False}, 422),
                ("wrong_digest_rejected", {"expected_activation_digest": "0" * 64}, 409),
                ("stale_mode_rejected", {"expected_mode_revision": revision - 1}, 409),
            ):
                response = controller.client.post(PREFIX, json={**body, **change})
                check(response.status_code == expected, name + " failed")
                checks[name] = True
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1100})
                check(
                    page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                    "Web approval page overflows",
                )
                page.screenshot(path=str(output / f"approval-{width}.png"), full_page=True)
            checks["real_modal_1440_and_390"] = True
            page.set_viewport_size({"width": 1440, "height": 1100})
            if activation_rescan:
                docker(
                    [
                        "exec",
                        identifier,
                        "/usr/bin/python3",
                        "-I",
                        "/opt/opsark-activation-lab/fixture.py",
                        "rescan-hold",
                    ]
                )
            page.locator("#service-activation-confirm").check()
            with page.expect_response(
                lambda r: urlsplit(r.url).path == PREFIX and r.request.method == "POST"
            ) as accepted:
                page.locator("#service-activation-execute").click()
            check(accepted.value.status == 200, "Web approval was not accepted")
            expect(page.locator("#service-activation-detail")).to_contain_text(
                "本次服务激活验证通过", timeout=90000
            )
            record = controller.client.get(PREFIX + f"/{HOST}/{plan['activation_id']}").json()
            notices = record["notification_count"]
            check(
                record["status"] == "verified"
                and (notices >= 1 if activation_rescan else notices == 1),
                "Controller did not retain its verified notification",
            )
            checks["real_web_explicit_approval_to_verified"] = True
            if activation_rescan:
                rescan_info = check_rescan(controller, page, identifier, output, plan, checks)
            root_after = probe(identifier)
            check(
                root_after["restart_intents"] == 1 and root_after["pid"] != before["pid"],
                "Root did not restart exactly once",
            )
            checks["native_single_restart_and_new_process"] = True
            checks["native_runtime_http_and_fresh_ssh"] = (
                root_after["runtime"]["status"] == "complete"
                and root_after["runtime"]["outdated_process_count"] == 0
                and root_after["health"]["passed"]
                and record["result"]["verification"]["fresh_ssh"]["passed"]
            )
            page.screenshot(path=str(output / "verified-1440.png"), full_page=True)
            with page.expect_download() as download:
                page.locator("#service-activation-detail").get_by_role(
                    "button", name="导出激活证据"
                ).click()
            download.value.save_as(str(output / "web-evidence.json"))
            evidence = json.loads((output / "web-evidence.json").read_text(encoding="utf-8"))
            check(
                evidence["kind"] == "opsark-service-activation-evidence"
                and evidence["bundle_digest"]
                == digest({k: v for k, v in evidence.items() if k != "bundle_digest"}),
                "Downloaded evidence digest mismatch",
            )
            checks["real_web_evidence_download"] = True
            rows_before = retained(controller.settings)
            controller.stop()
            controller.start()
            # The console deliberately keeps its token only in page memory.
            # Reauthenticate through the real login form after the process restart.
            login(page, controller)
            page.locator(f"[data-service-activation-query='{plan['activation_id']}']").click()
            expect(page.locator("#service-activation-detail")).to_contain_text(
                "本次服务激活验证通过"
            )
            cached = controller.client.get(PREFIX + f"/{HOST}/{plan['activation_id']}").json()
            check(
                cached["status"] == "verified" and cached["notification_count"] == notices,
                "Controller restart lost or duplicated the result",
            )
            check(controller.pids[0] != controller.pids[1], "Controller process did not restart")
            checks["real_controller_restart_preserves_result"] = True
            if activation_rescan:
                retained_bundle = controller.client.get(
                    PREFIX + f"/{HOST}/{plan['activation_id']}/evidence"
                ).json()
                check(
                    retained_bundle["evidence_status"] == "internally_consistent"
                    and retained_bundle["rescan_request"] == rescan_info["rescan_request"],
                    "Restart changed the original completed rescan association",
                )
                checks["rescan_association_preserved_after_restart"] = True
            check(
                retained(controller.settings) == rows_before,
                "Restart changed parent/pause SQL rows",
            )
            modes(page, controller, "manual")
            page.set_viewport_size({"width": 390, "height": 1100})
            check(
                page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                "Verified page overflows on mobile",
            )
            page.screenshot(path=str(output / "verified-390.png"), full_page=True)
            checks["manual_closeout_via_web"] = True
            check(not failures, "Browser page errors: " + str(failures))
            check(
                len([r for r in requests if r["method"] == "POST" and r["path"] == PREFIX]) == 1,
                "Browser replayed the approval",
            )
            check(
                len(
                    [
                        r
                        for r in requests
                        if r["method"] == "POST" and r["path"] == PREFIX + "/plans"
                    ]
                )
                == 3,
                "Unexpected browser preview count",
            )
            checks["one_browser_submit_no_mock_no_page_errors"] = True
            save(output / "web-requests.json", requests)
            save(output / "web-responses.json", responses)
            save(output / "web-final-record.json", cached)
            return checks, {
                "activation_id": plan["activation_id"],
                "browser_version": browser.version,
                "notification_count": cached["notification_count"],
                "manual_preview_id": manual["activation_id"],
                "canceled_preview_id": canceled["activation_id"],
                "controller_pids": controller.pids,
                "evidence_status": evidence["evidence_status"],
                **({"rescan": rescan_info} if activation_rescan else {}),
            }
        finally:
            save(output / "web-requests.json", requests)
            save(output / "web-responses.json", responses)
            save(output / "page-errors.json", failures)
            context.close()
            browser.close()


def run_web(identifier, output, *, image, browser_name, activation_rescan=False):
    began = time.monotonic()
    token = json.loads((output / "provenance.json").read_text())["run_id"]
    inspect_owned(identifier, token)
    before = probe(identifier)
    check(
        before["os"]["ID"] == "debian" and before["os"]["VERSION_ID"] == image.split(":")[1],
        "Actual guest distribution mismatch",
    )
    check(
        before["runtime"]["outdated_process_count"] == 1 and before["restart_intents"] == 0,
        "Unexpected guest activation start state",
    )
    save(output / "web-before.json", before)
    with tempfile.TemporaryDirectory(prefix="opsark-web-activation-") as temporary:
        directory = Path(temporary).resolve()
        with ssh_relay(identifier) as port:
            settings = configure(
                directory, identifier, port, before, activation_rescan=activation_rescan
            )
            original_sql = retained(settings)
            controller = Controller(settings, directory)
            try:
                controller.start()
                checks, info = run_browser(
                    controller,
                    identifier,
                    output,
                    browser_name,
                    before,
                    activation_rescan=activation_rescan,
                )
                after = probe(identifier)
                save(output / "web-after.json", after)
                check(
                    before["parent_sha256"] == after["parent_sha256"],
                    "Root parent/pause bytes changed",
                )
                checks["root_parent_plan_manifest_pause_bytes_preserved"] = True
                check(original_sql == retained(settings), "Controller original SQL rows changed")
                checks["controller_parent_and_pause_sql_preserved"] = True
                check(
                    before["inventory_digest"] == after["inventory_digest"], "Package state changed"
                )
                checks["no_package_changes"] = True
                submits = [r for r in after["rpc"] if r["request"]["op"] == "activation_submit"]
                check(
                    len(submits) == 1
                    and submits[0]["request"]["activation_id"] == info["activation_id"],
                    "More than one native activation submission",
                )
                checks["root_audit_one_submit_original_id"] = True
                if activation_rescan:
                    scan_calls = [r for r in after["rpc"] if r["request"]["op"] == "scan"]
                    check(
                        len(scan_calls) == info["rescan"]["scan_rpc_count_before_restart"],
                        "Controller restart or evidence read replayed a scan",
                    )
                    checks["cached_exports_and_restart_do_not_replay_scan"] = True
                check(
                    after["mode"]["mode"] == "manual" and after["safety"]["paused"],
                    "Final manual/pause state changed",
                )
                check(all(checks.values()), "One or more real Web checks failed")
                result = {
                    "schema_version": 1,
                    "evidence_origin": "controlled_lab",
                    "passed": True,
                    "classification": "real_activation_native_rescan_synthetic_parent"
                    if activation_rescan
                    else "real_web_api_paramiko_root_activation_synthetic_parent_vendor",
                    "image_requested": image,
                    "os": after["os"],
                    "architecture": after["architecture"],
                    "browser": browser_name,
                    **info,
                    "before_pid": before["pid"],
                    "after_pid": after["pid"],
                    "check_count": len(checks),
                    "checks": checks,
                    "elapsed_seconds": round(time.monotonic() - began, 3),
                    "source_sha256": after["source_sha256"],
                    "controller_source_sha256": {
                        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted((ROOT / "src/opsark").rglob("*.py"))
                    },
                    "web_source_sha256": {
                        n: hashlib.sha256((ROOT / "web" / n).read_bytes()).hexdigest()
                        for n in ("index.html", "app.js", "styles.css")
                    },
                    "isolation": (
                        "network=none; guest loopback SSH via byte-only host loopback relay"
                    ),
                    "limitations": [
                        "synthetic_parent_and_vendor_finding",
                        "no_debian_patch_installation",
                        "no_official_debian_vendor_assessment",
                        "shared_host_kernel",
                        "no_official_debian_vendor_assessment_on_rescan"
                        if activation_rescan
                        else "vulnerability_watch_disabled",
                    ],
                }
                save(output / "web-result.json", result)
                print(json.dumps(result, sort_keys=True), flush=True)
            finally:
                controller.close()
                shutil.copyfile(directory / "controller.log", output / "controller.log")
                target = output / "controller-state"
                target.mkdir(exist_ok=True)
                for database in settings.data_dir.glob("*.sqlite3"):
                    with (
                        closing(sqlite3.connect(database)) as source,
                        closing(sqlite3.connect(target / database.name)) as dest,
                    ):
                        source.backup(dest)


def offline_exports(output):
    """Run only after the guest/controller are gone; originals are never modified."""
    entry = ROOT / "tools/verify_activation_evidence.py"

    def verify(path):
        result = subprocess.run(  # noqa: S603 -- fixed offline verifier and owned artifact.
            [sys.executable, str(entry), str(path)],
            cwd=output,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result.returncode, json.loads(result.stdout)

    code, valid = verify(output / "web-evidence.json")
    check(
        code == 0 and valid["valid"] and valid["status"] == "internally_consistent",
        "Offline verification of the downloaded original failed",
    )
    code, pending = verify(output / "web-evidence-pending.json")
    check(code == 2 and pending["status"] == "incomplete", "Pending export was promoted offline")
    original = json.loads((output / "web-evidence.json").read_text(encoding="utf-8"))
    copies = output / "offline-checks"
    copies.mkdir(exist_ok=False)
    negative = []
    for name, change in (
        ("wrong-original-job", lambda b: b["rescan_request"].update(original_job_id="0" * 32)),
        ("wrong-scan", lambda b: b["rescan_request"].update(result_scan_id="0" * 32)),
        (
            "changed-native-facts",
            lambda b: b["observations"][0]["collection_evidence"]["facts"].update(
                apt_state_digest="0" * 64
            ),
        ),
        (
            "unearned-vendor-label",
            lambda b: b["evidence_provenance"]["rescan_observations"][0].update(
                assessment_kind="vendor_records"
            ),
        ),
        ("missing-observation", lambda b: b.update(observations=[])),
    ):
        value = copy.deepcopy(original)
        change(value)
        value["bundle_digest"] = digest({k: v for k, v in value.items() if k != "bundle_digest"})
        path = copies / (name + ".json")
        save(path, value)
        code, report = verify(path)
        check(code == 2 and report["status"] == "invalid", "Resealed copy was accepted: " + name)
        negative.append({"copy": name, "status": report["status"]})
    report = {
        "passed": True,
        "verified_after_guest_cleanup": True,
        "original": valid,
        "pending": pending,
        "rejected_copies": negative,
    }
    save(output / "offline-verification.json", report)
    print(
        json.dumps({"offline_export_verification": True, "rejected_copies": len(negative)}),
        flush=True,
    )
