"""Actual local main process + Chromium + SSH; all remote metadata is synthetic.

Explicit pytest entry, not an actual Docker/systemd/VM acceptance. The child has
no model configuration, permits only loopback sockets, and denies HTTP clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import paramiko
import pytest
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from opsark.collector import commands_for_preflight  # noqa: E402
from opsark.compose_discovery import commands_for_compose_discovery  # noqa: E402
from opsark.config import Settings, load_hosts  # noqa: E402
from opsark.platforms import TOOLS  # noqa: E402

SOURCES = (
    "src/opsark/main.py",
    "src/opsark/ai_provider.py",
    "src/opsark/config.py",
    "src/opsark/collector.py",
    "src/opsark/host_preflight.py",
    "src/opsark/compose_discovery.py",
    "src/opsark/host_onboarding.py",
    "deploy/readonly/export_policy.py",
    "web/app.js",
    "web/index.html",
    "web/styles.css",
    "web/defense.js",
    "tests/compose_discovery_live_lab.py",
)
TOKEN = "synthetic-local-compose-live-console-token"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    return {name: digest(ROOT / name) for name in SOURCES}


def write_json(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_bytes((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
    os.replace(temporary, path)


def windows_kernel():
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel


def creation_time(kernel, handle):
    import ctypes
    from ctypes import wintypes

    values = [wintypes.FILETIME() for _ in range(4)]
    assert kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values))
    return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime


def runtime_identity():
    kernel = windows_kernel() if os.name == "nt" else None
    return {
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "creation_filetime": creation_time(kernel, kernel.GetCurrentProcess()) if kernel else None,
    }


def bind_runtime(identity, launcher):
    assert identity["pid"] == launcher.pid or (
        os.name == "nt" and identity["parent_pid"] == launcher.pid
    )
    if os.name != "nt":
        return None
    kernel = windows_kernel()
    handle = kernel.OpenProcess(0x101001, False, identity["pid"])
    assert handle
    try:
        assert creation_time(kernel, handle) == identity["creation_filetime"]
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return kernel, handle


def install_model_guard(audit):
    """Count and deny the actual shared dispatch sink, before any provider I/O."""
    from opsark import ai_provider

    async def deny_model(body, settings, maximum, seconds):
        audit["model_calls"] += 1
        raise RuntimeError("local_lab_model_dispatch_forbidden")

    # Deliberate runtime test hook; identity is checked on installation and exit.
    setattr(ai_provider, "_request", deny_model)  # noqa: B010
    audit["model_guard_installed"] = ai_provider._request is deny_model
    return deny_model


def storage(directory):
    result = {}
    for path in sorted(directory.rglob("*.sqlite3")):
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            rows, counts = {}, {}
            for (table,) in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                # Only this new local store's catalog supplies the quoted identifier.
                query = "SELECT * FROM " + quoted  # noqa: S608
                values = connection.execute(query).fetchall()
                counts[table] = len(values)
                rows[table] = sorted(repr(value) for value in values)
            encoded = json.dumps(rows, sort_keys=True).encode()
            result[str(path.relative_to(directory))] = {
                "logical_sha256": hashlib.sha256(encoded).hexdigest(),
                "table_counts": counts,
            }
    assert result
    return result


class MetadataSSH(paramiko.ServerInterface):
    def __init__(self, owner):
        self.owner = owner

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        if username == "opsark-readonly" and key == self.owner.user_key:
            self.owner.counts["authenticated"] += 1
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        name = self.owner.allowed.get(command)
        if name is None:
            self.owner.counts["unknown_exec"] += 1
            return False
        self.owner.counts["exec"] += 1
        self.owner.names.append(name)
        if name == "compose_inventory":
            self.owner.counts["inventory"] += 1
            output = (
                json.dumps(
                    {
                        "id": "a" * 64,
                        "name": "demo-api-1",
                        "state": "running",
                        "project": "demo",
                        "service": "api",
                        "ports": f"127.0.0.1:{self.owner.host_port}->8000/tcp, "
                        f"[::1]:{self.owner.host_port}->8000/tcp",
                    }
                )
                + "\n"
            )
        else:
            output = self.owner.outputs[name]

        def respond():
            with contextlib.suppress(OSError, EOFError):
                channel.sendall(output.encode())
                channel.send_exit_status(0)
                channel.shutdown_write()

        threading.Thread(target=respond, daemon=True).start()
        return True


class LocalSSH:
    """Repeated real SSH connections; no shell or subprocess exists server-side."""

    def __init__(self, directory):
        self.directory = directory
        self.server_key = paramiko.RSAKey.generate(2048)
        self.user_key = paramiko.RSAKey.generate(2048)
        self.key_path = directory / "synthetic-private-key"
        self.user_key.write_private_key_file(str(self.key_path))
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(12)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.connections, self.threads, self.names = [], [], []
        self.allowed, self.outputs = {}, {}
        self.host_port = 8081
        self.counts = {
            key: 0 for key in ("connections", "authenticated", "exec", "inventory", "unknown_exec")
        }
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, peer = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            assert ipaddress.ip_address(peer[0]).is_loopback
            self.counts["connections"] += 1
            transport = paramiko.Transport(connection)
            self.connections.append(transport)

            def session(current=transport):
                channels = []
                try:
                    current.add_server_key(self.server_key)
                    current.start_server(server=MetadataSSH(self))
                    while current.is_active() and not self.stop.is_set():
                        channel = current.accept(0.1)
                        if channel is not None:
                            channels.append(channel)
                except (OSError, EOFError, paramiko.SSHException):
                    pass
                finally:
                    current.close()

            thread = threading.Thread(target=session, daemon=True)
            self.threads.append(thread)
            thread.start()

    def prepare(self):
        public = self.server_key.get_name() + " " + self.server_key.get_base64()
        (self.directory / "synthetic-known-hosts").write_text(
            f"[127.0.0.1]:{self.port} {public}\n", encoding="ascii"
        )
        wrong = paramiko.RSAKey.generate(2048)
        (self.directory / "synthetic-wrong-known-hosts").write_text(
            f"[127.0.0.1]:{self.port} {wrong.get_name()} {wrong.get_base64()}\n", encoding="ascii"
        )
        inventory = self.directory / "inventory.toml"
        inventory.write_text(
            '[credentials.good]\nkey_file="synthetic-private-key"\n'
            'known_hosts_file="synthetic-known-hosts"\n'
            '[credentials.wrong]\nkey_file="synthetic-private-key"\n'
            'known_hosts_file="synthetic-wrong-known-hosts"\n'
            + "".join(
                f'[[hosts]]\nid="{name}"\naddress="127.0.0.1"\nport={self.port}\n'
                f'username="opsark-readonly"\nsite_domain="site.invalid"\ncredential="{credential}"\n'
                'compose_project="demo"\ncontainer_binding_confirmed=false\n'
                for name, credential in (("pending", "good"), ("wrong-pin", "wrong"))
            ),
            encoding="ascii",
        )
        target = load_hosts(
            Settings(data_dir=self.directory / "unused", token=TOKEN, inventory_path=inventory)
        )["pending"]
        probes = commands_for_preflight(target)
        assert "container_state" not in probes
        probes.update(commands_for_compose_discovery(target, "demo"))
        self.allowed = {("LC_ALL=C " + command).encode(): name for name, command in probes.items()}
        assert not any(b" inspect " in command or b" logs " in command for command in self.allowed)
        self.outputs = {
            "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
            "platform_tools": "OPSARK_ARCH=x86_64\n"
            + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS),
            "nginx_status": "active\n",
            "compose_version": "v2.31.0\n",
            "docker_rootful": (
                '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}\n'
            ),
            "disk_bytes": (
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                "/dev/test 100000 12000 88000 12% /\n"
            ),
            "disk_inodes": (
                "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/test 10000 1100 8900 11% /\n"
            ),
        }
        self.thread.start()
        return inventory

    def close(self):
        self.stop.set()
        self.listener.close()
        for connection in self.connections:
            connection.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
        for thread in self.threads:
            thread.join(timeout=3)
        assert not self.thread.is_alive() and all(not thread.is_alive() for thread in self.threads)
        self.key_path.unlink(missing_ok=True)


def child():
    import uvicorn

    config = json.loads(sys.stdin.readline())
    assert set(config) == {"directory", "inventory"}
    directory, inventory = Path(config["directory"]), Path(config["inventory"])
    assert directory.is_absolute() and inventory.parent == directory.parent
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    os.environ["OPSARK_DATA_DIR"] = str(directory / "bootstrap")
    os.environ["OPSARK_TOKEN"] = TOKEN
    audit = {
        "nonloopback_attempts": 0,
        "outbound_http_attempts": 0,
        "model_calls": 0,
        "forbidden_http_writes": 0,
        "stopped": False,
    }
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def address_ok(address):
        try:
            return type(address) is tuple and ipaddress.ip_address(address[0]).is_loopback
        except ValueError:
            return False

    def connect(current, address):
        if not address_ok(address):
            audit["nonloopback_attempts"] += 1
            raise OSError("nonloopback_forbidden")
        return original_connect(current, address)

    def connect_ex(current, address):
        if not address_ok(address):
            audit["nonloopback_attempts"] += 1
            raise OSError("nonloopback_forbidden")
        return original_connect_ex(current, address)

    def deny_http(*_args, **_kwargs):
        audit["outbound_http_attempts"] += 1
        raise OSError("outbound_http_forbidden")

    async def deny_async_http(*_args, **_kwargs):
        return deny_http()

    socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
    httpx.Client.send, httpx.AsyncClient.send = deny_http, deny_async_http
    from opsark import ai_provider
    from opsark.main import create_app

    model_guard = install_model_guard(audit)

    settings = Settings(data_dir=directory / "active", token=TOKEN, inventory_path=inventory)
    assert all(
        getattr(settings, name) is False
        for name in (
            "observation_enabled",
            "web_observation_enabled",
            "vulnerability_scan_enabled",
            "defense_worker_enabled",
            "defense_task_watch_enabled",
            "defense_session_enabled",
        )
    )
    assert all(
        getattr(settings, name) is None
        for name in (
            "ai_base_url",
            "ai_key",
            "ai_model",
            "ai_key_file",
            "patch_inventory_path",
            "defense_inventory_path",
            "defense_policy_path",
        )
    )
    application = create_app(settings)

    @application.middleware("http")
    async def permit_request(request, call_next):
        allowed = {
            "/api/hosts/pending/preflight",
            "/api/hosts/pending/compose-discovery",
            "/api/hosts/pending/compose-discovery/preview",
            "/api/hosts/wrong-pin/compose-discovery",
        }
        if request.method not in {"GET", "HEAD"} and not (
            request.method == "POST" and request.url.path in allowed
        ):
            audit["forbidden_http_writes"] += 1
            raise ValueError("unexpected_http_write")
        return await call_next(request)

    listener = socket.socket()
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
            log_level="critical",
            timeout_graceful_shutdown=3,
        )
    )

    def stop():
        sys.stdin.readline()
        server.should_exit = True

    threading.Thread(target=stop, daemon=True).start()
    write_json(directory / "ready.safe.json", {**runtime_identity(), "port": port})
    try:
        server.run(sockets=[listener])
    finally:
        audit["stopped"] = True
        audit["model_guard_installed"] = ai_provider._request is model_guard
        audit["pid"] = os.getpid()
        write_json(directory / "child-audit.safe.json", audit)


@pytest.fixture
def live(tmp_path):
    before = source_hashes()
    write_json(tmp_path / "source-before.safe.json", before)
    ssh = LocalSSH(tmp_path)
    process = None
    runtime = None
    runtime_pid = None
    ssh_logger = logging.getLogger("paramiko")
    previous_log_level = ssh_logger.level
    ssh_logger.setLevel(logging.CRITICAL)
    record = {
        "schema": "opsark-compose-discovery-local-live/v1",
        "completed": False,
        "real_main_process": True,
        "real_loopback_ssh": True,
        "synthetic_metadata_only": True,
        "actual_docker_or_vm_verified": False,
    }
    try:
        inventory = ssh.prepare()
        refs = {
            path.name: digest(path)
            for path in (
                inventory,
                tmp_path / "synthetic-known-hosts",
                tmp_path / "synthetic-wrong-known-hosts",
            )
        }
        directory = tmp_path / "controller"
        directory.mkdir()
        environment = {
            name: value for name, value in os.environ.items() if not name.startswith("OPSARK_")
        }
        process = subprocess.Popen(  # noqa: S603 -- fixed local source, synthetic stdin only.
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert process.stdin is not None
        process.stdin.write(
            (json.dumps({"directory": str(directory), "inventory": str(inventory)}) + "\n").encode()
        )
        process.stdin.flush()
        ready = directory / "ready.safe.json"
        deadline = time.monotonic() + 20
        while not ready.exists():
            assert process.poll() is None, "local_main_child_start_failed"
            assert time.monotonic() < deadline, "local_main_child_start_timeout"
            time.sleep(0.05)
        handshake = json.loads(ready.read_bytes())
        runtime = bind_runtime(handshake, process)
        runtime_pid = handshake["pid"]
        record["runtime_identity_bound"] = True
        base = "http://127.0.0.1:" + str(handshake["port"])
        with httpx.Client(
            base_url=base, trust_env=False, timeout=12, headers={"Authorization": "Bearer " + TOKEN}
        ) as client:
            while True:
                try:
                    if client.get("/api/status").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                assert time.monotonic() < deadline
                time.sleep(0.05)
            capabilities = client.get("/api/capabilities").json()
            assert capabilities["model_configured"] is False
            yield base, client, ssh, record, directory
        assert refs == {
            path.name: digest(path)
            for path in (
                inventory,
                tmp_path / "synthetic-known-hosts",
                tmp_path / "synthetic-wrong-known-hosts",
            )
        }
        record["registration_and_pin_files_unchanged"] = True
    finally:
        if process is not None:
            if process.poll() is None:
                assert process.stdin is not None
                with contextlib.suppress(OSError):
                    process.stdin.write(b"stop\n")
                    process.stdin.flush()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    if runtime is not None:
                        kernel, handle = runtime
                        if kernel.WaitForSingleObject(handle, 0) != 0:
                            kernel.TerminateProcess(handle, 71)
                    process.kill()
                    process.wait(timeout=5)
            record["child_exit_code"] = process.returncode
            if runtime is not None:
                kernel, handle = runtime
                record["runtime_stopped"] = kernel.WaitForSingleObject(handle, 5000) == 0
                kernel.CloseHandle(handle)
            else:
                record["runtime_stopped"] = process.returncode == 0
            audit_path = tmp_path / "controller/child-audit.safe.json"
            if audit_path.is_file():
                audit = json.loads(audit_path.read_bytes())
                record["audit_runtime_matches"] = audit.pop("pid") == runtime_pid
                record["child_audit"] = audit
        ssh.close()
        ssh_logger.setLevel(previous_log_level)
        record["ssh_stopped"] = True
        record["ssh_counts"] = ssh.counts
        record["ssh_command_names"] = ssh.names
        record["source_before"] = before
        record["source_after"] = source_hashes()
        record["source_unchanged"] = record["source_before"] == record["source_after"]
        record["completed"] = bool(
            record["completed"]
            and record["source_unchanged"]
            and record.get("registration_and_pin_files_unchanged")
            and record.get("child_exit_code") == 0
            and record.get("runtime_identity_bound") is True
            and record.get("runtime_stopped") is True
            and record.get("audit_runtime_matches") is True
            and record.get("child_audit")
            == {
                "nonloopback_attempts": 0,
                "outbound_http_attempts": 0,
                "model_calls": 0,
                "model_guard_installed": True,
                "forbidden_http_writes": 0,
                "stopped": True,
            }
            and ssh.counts["unknown_exec"] == 0
        )
        write_json(tmp_path / "source-after.safe.json", record["source_after"])
        write_json(tmp_path / "acceptance.safe.json", record)
        assert record["source_unchanged"]
        assert record.get("child_exit_code") == 0
        assert record.get("child_audit") == {
            "nonloopback_attempts": 0,
            "outbound_http_attempts": 0,
            "model_calls": 0,
            "model_guard_installed": True,
            "forbidden_http_writes": 0,
            "stopped": True,
        }
        assert ssh.counts["unknown_exec"] == 0
        assert record["completed"] is True


def test_model_guard_counts_actual_dispatch_sink_before_refusing(monkeypatch, tmp_path):
    from opsark import ai_provider

    before = source_hashes()
    write_json(tmp_path / "source-before.safe.json", before)
    monkeypatch.setattr(ai_provider, "_request", ai_provider._request)
    audit = {"model_calls": 0}
    installed = install_model_guard(audit)
    assert ai_provider._request is installed and audit["model_guard_installed"] is True
    with pytest.raises(RuntimeError, match="^local_lab_model_dispatch_forbidden$"):
        asyncio.run(ai_provider._request({}, None, 1, 1))
    assert audit["model_calls"] == 1
    after = source_hashes()
    assert before == after
    write_json(tmp_path / "source-after.safe.json", after)
    write_json(
        tmp_path / "model-guard.safe.json",
        {
            "schema": "opsark-compose-live-model-guard-self-test/v1",
            "pure_fake_direct_sink_only": True,
            "actual_provider_contact": False,
            "model_guard_installed": True,
            "model_dispatch_attempts": 1,
            "fixed_refusal_observed": True,
            "source_before": before,
            "source_after": after,
            "source_unchanged": True,
        },
    )


@pytest.mark.parametrize("width", [1440, 320])
def test_local_main_browser_loopback_discovery_and_fresh_preview(live, tmp_path, width):
    base, client, ssh, record, directory = live
    counts = {"discovery": 0, "preview": 0, "preflight": 0, "external": 0, "forbidden_write": 0}
    record["browser_counts"] = counts
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": width, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))

        def guard(route):
            request = route.request
            if not request.url.startswith(base + "/"):
                counts["external"] += 1
                route.abort()
                return
            path = urlsplit(request.url).path
            allowed = {
                "/api/hosts/pending/compose-discovery": "discovery",
                "/api/hosts/pending/compose-discovery/preview": "preview",
                "/api/hosts/pending/preflight": "preflight",
            }
            if request.method not in {"GET", "HEAD"}:
                if request.method != "POST" or path not in allowed:
                    counts["forbidden_write"] += 1
                    route.abort()
                    return
                counts[allowed[path]] += 1
            route.continue_()

        page.route("**/*", guard)
        try:
            page.goto(base)
            page.locator("#token-input").fill(TOKEN)
            page.locator("#login-button").click()
            expect(page.locator("#app-shell")).to_be_visible()
            page.locator('button[data-view="hosts"]').click()
            card = page.locator('[data-host-id="pending"]')
            expect(card).to_contain_text("容器待确认")
            expect(page.locator("#automation-current")).to_contain_text("手动模式")
            before = storage(directory)
            assert ssh.counts["exec"] == 0
            card.locator("[data-host-preflight]").click()
            expect(card.locator('[data-check-id="container_state"]')).to_contain_text(
                "容器登记尚未确认"
            )
            assert ssh.names.count("container_state") == 0
            assert ssh.names.count("container_logs") == 0
            panel = card.locator("[data-compose-host]")
            panel.locator("[data-compose-discover]").click()
            candidate = (
                panel.locator("[data-compose-candidate] option").nth(1).get_attribute("value")
            )
            panel.locator("[data-compose-candidate]").select_option(candidate)
            panel.locator("[data-compose-port]").select_option("8081")
            assert ssh.counts["inventory"] == 1
            panel.locator("[data-compose-preview]").click()
            expect(panel.locator("[data-compose-fragment]")).to_have_text(
                'compose_project = "demo"\ncontainer_name = "demo-api-1"\n'
                "container_binding_confirmed = true\nexpected_upstream_port = 8081\n"
            )
            assert ssh.counts["inventory"] == 2
            ssh.host_port = 8082
            with page.expect_response(
                lambda response: response.url.endswith("/compose-discovery/preview")
            ) as stale:
                panel.locator("[data-compose-preview]").click()
            assert stale.value.status == 409
            expect(panel).to_contain_text("旧候选已失效")
            expect(panel.locator("[data-compose-candidate]")).to_have_count(0)
            expect(panel.locator("[data-compose-fragment]")).to_have_count(0)
            assert ssh.counts["inventory"] == 3
            panel.locator("[data-compose-discover]").click()
            fresh_candidate = (
                panel.locator("[data-compose-candidate] option").nth(1).get_attribute("value")
            )
            assert fresh_candidate is not None and fresh_candidate != candidate
            panel.locator("[data-compose-candidate]").select_option(fresh_candidate)
            panel.locator("[data-compose-port]").select_option("8082")
            panel.locator("[data-compose-preview]").click()
            expect(panel.locator("[data-compose-fragment]")).to_have_text(
                'compose_project = "demo"\ncontainer_name = "demo-api-1"\n'
                "container_binding_confirmed = true\nexpected_upstream_port = 8082\n"
            )
            assert ssh.counts["inventory"] == 5
            expect(card).to_contain_text("容器待确认")
            listed = [host for host in client.get("/api/hosts").json() if host["source"] == "ssh"]
            assert {host["id"] for host in listed} == {"pending", "wrong-pin"}
            assert all(host["container_binding_confirmed"] is False for host in listed)
            assert all("compose_project" not in host for host in listed)
            after = storage(directory)
            assert before == after
            assert not errors
            assert counts == {
                "discovery": 2,
                "preview": 3,
                "preflight": 1,
                "external": 0,
                "forbidden_write": 0,
            }
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
            page.screenshot(path=str(tmp_path / f"live-compose-{width}.png"), full_page=True)
            record.update(
                completed=True,
                viewport_width=width,
                browser_counts=counts,
                sqlite_history_unchanged=True,
                storage_before=before,
                storage_after=after,
                preview_fresh_ssh_collections=3,
                stale_http_status=409,
                pending_container_preserved=True,
                candidate_fragment_lines=4,
            )
        finally:
            context.close()
            browser.close()


def test_local_main_wrong_pin_issues_zero_exec(live):
    _, client, ssh, record, directory = live
    before = storage(directory)
    assert ssh.counts["exec"] == 0
    response = client.post("/api/hosts/wrong-pin/compose-discovery", json={})
    assert response.status_code == 200
    value = response.json()
    assert value["status"] == "unavailable" and value["reason"] == "connection_failed"
    assert value["candidates"] == [] and value["snapshot_digest"] is None
    assert ssh.counts["exec"] == 0 and ssh.counts["inventory"] == 0
    assert before == storage(directory)
    record.update(completed=True, wrong_pin_zero_exec=True, sqlite_history_unchanged=True)


if __name__ == "__main__":
    assert sys.argv[1:] == ["--child"]
    child()
