"""Verify business-readiness receipts and API on fresh, pinned Docker fixtures."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
HOST = "readiness-lab"
DOMAIN = "readiness.opsark.invalid"
ACCOUNT = "opsark-readonly"
PORT = 42180
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
STAGE = "/run/opsark-readiness-lab"
API = f"/api/hosts/{HOST}/business-readiness"
LIMITS = (
    "--pull",
    "never",
    "--no-healthcheck",
    "--pids-limit",
    "64",
    "--memory",
    "128m",
    "--cpus",
    "0.5",
    "--log-driver",
    "none",
)
LOCKED = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true")
PYTHON_IMAGE = "/app/.venv/bin/python"
CONTROLLER = """import os
import socket
import sys
from pathlib import Path
from threading import Thread

state = Path(os.environ['OPSARK_DATA_DIR'])

def mark(stage):
    (state / 'startup-stage').write_text(stage, encoding='ascii')

def detect(listener):
    with listener.accept()[0]:
        (state / 'ai-contacted').touch()

with socket.socket() as ai:
    ai.bind(('127.0.0.1', 0))
    ai.listen()
    Thread(target=detect, args=(ai,), daemon=True).start()
    os.environ['OPSARK_AI_BASE_URL'] = f'http://127.0.0.1:{ai.getsockname()[1]}/v1'
    mark('importing')
    try:
        import uvicorn
        from opsark import main

        if os.environ.get('PYTHONPATH') == '/app/src' and (
            Path(main.__file__).resolve() != Path('/app/src/opsark/main.py')
            or not Path('/app/web/app.js').is_file()
        ):
            raise RuntimeError('The controller must use baked application files')

        mark('serving')
        config = uvicorn.Config(main.app, host='127.0.0.1', port=8010, access_log=False)
        listener = [socket.socket(fileno=int(sys.argv[1]))] if len(sys.argv) == 2 else None
        uvicorn.Server(config).run(sockets=listener)
    except (Exception, SystemExit) as error:
        kind = type(error).__name__
        if kind.isascii() and kind.isidentifier():
            (state / 'startup-failed').write_text(kind, encoding='ascii')
        raise
"""
NGINX = """daemon off;
worker_processes 1;
pid /run/opsark-nginx-live/nginx.pid;
error_log stderr crit;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path /run/opsark-nginx-live/client;
    proxy_temp_path /run/opsark-nginx-live/proxy;
    fastcgi_temp_path /run/opsark-nginx-live/fastcgi;
    uwsgi_temp_path /run/opsark-nginx-live/uwsgi;
    scgi_temp_path /run/opsark-nginx-live/scgi;
    server {
        listen 127.0.0.1:42180 default_server;
        return 404;
    }
    server {
        listen 127.0.0.1:42180;
        server_name readiness.opsark.invalid;
        location = /healthz { return 200 "STATIC_BODY"; }
        location = /application { proxy_pass http://127.0.0.1:42181; }
        location / { return 404; }
    }
}
"""
UPSTREAM = """import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        mode = Path(__file__).with_name('mode').read_text('ascii')
        if mode in ('failed', 'timeout'):
            if mode == 'timeout':
                time.sleep(3)
            self.close_connection = True
            return
        body = b'EXPECTED_BODY' if mode == 'healthy' else b'WRONG_BODY'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(('127.0.0.1', 42181), Handler).serve_forever()
"""
SSHD = f"""Port 22
ListenAddress 0.0.0.0
HostKey {STAGE}/host-key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AllowUsers {ACCOUNT}
AuthorizedKeysFile .ssh/authorized_keys
DisableForwarding yes
PermitTTY no
LogLevel QUIET
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def require_root(root):
    base = Path("/var/lib/opsark-release-lab")
    require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and root != base
        and root.is_absolute()
        and root.is_relative_to(base)
        and root.resolve() == root,
        "An administrator-owned fixture laboratory is required",
    )
    for path in (root, *root.parents):
        info = path.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "The fixture laboratory path is not trusted",
        )
    require(not root.stat().st_mode & 0o077, "The fixture laboratory must be private")


def run(argv, *, allowed=True):
    result = subprocess.run(  # noqa: S603 -- fixed local tools and owned fixture arguments.
        argv, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=15, check=False
    )
    require(not allowed or result.returncode == 0, f"Fixture command failed ({argv[0]})")
    return result


def stage(docker, container, local, name, contents):
    path = local / name
    path.write_text(contents, encoding="ascii")
    docker("cp", str(path), f"{container}:{STAGE}/{name}")


def ssh(docker_host, local, command, *, pinned="known_hosts"):
    return run(
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={local / pinned}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-i",
            str(local / "collector"),
            f"{ACCOUNT}@{docker_host}",
            command,
        ],
        allowed=False,
    )


def source_mount(directory):
    return f"type=bind,src={ROOT / directory},dst=/fixture-code/{directory},readonly"


def export(docker, image, local, *, baked=False):
    if image is None:
        from deploy.readonly.export_policy import export_policy

        export_policy(local / "inventory.toml", HOST, local / "policy.json")
        return
    exporter = "/fixture-code/deploy/readonly/export_policy.py"
    if baked:
        source = ROOT / "deploy/readonly/export_policy.py"
        mounts = (
            "--env",
            "PYTHONPATH=/app/src",
            "--mount",
            f"type=bind,src={source},dst={exporter},readonly",
        )
    else:
        mounts = ("--mount", source_mount("src"), "--mount", source_mount("deploy"))
    docker(
        "run",
        "--rm",
        "--network",
        "none",
        *LIMITS,
        *LOCKED,
        "--user",
        "0:0",
        *mounts,
        "--mount",
        f"type=bind,src={local},dst=/fixture",
        "--entrypoint",
        PYTHON_IMAGE,
        image,
        "-B",
        exporter,
        "--inventory",
        "/fixture/inventory.toml",
        "--host-id",
        HOST,
        "--output",
        "/fixture/policy.json",
    )


def guest_address(docker, guest):
    address = ipaddress.IPv4Address(
        docker(
            "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", guest
        ).decode("ascii")
    )
    require(address.is_private, "Fixture bridge must be private")
    return str(address)


def prepare_guest(docker, guest, local, address, bodies, controller_image, *, baked=False):
    def execute(*args):
        return docker("exec", guest, *args)

    execute("/usr/bin/install", "-d", "-m", "0700", STAGE)
    execute("/usr/bin/install", "-d", "-m", "0755", "/run/sshd")
    execute("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{STAGE}/host-key")
    run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(local / "collector")])
    host_key = execute("/usr/bin/cat", f"{STAGE}/host-key.pub").decode("ascii").split()[:2]
    require(len(host_key) == 2 and host_key[0] == "ssh-ed25519", "Missing out-of-band host key")
    (local / "known_hosts").write_text(f"{address} {' '.join(host_key)}\n", encoding="ascii")
    collector_public = local / "collector.pub"
    other_key = " ".join(collector_public.read_text(encoding="ascii").split()[:2])
    (local / "wrong_known_hosts").write_text(f"{address} {other_key}\n", encoding="ascii")

    inventory = local / "inventory.toml"
    inventory.write_text(
        f'[credentials.lab]\nkey_file = "collector"\nknown_hosts_file = "known_hosts"\n'
        f'[[hosts]]\nid = "{HOST}"\naddress = "{address}"\nusername = "{ACCOUNT}"\n'
        f'site_domain = "{DOMAIN}"\ncredential = "lab"\n'
        + "".join(
            f'[[hosts.business_checks]]\nid = "{check}"\ndomain = "{DOMAIN}"\nport = {PORT}\n'
            f'path = "{path}"\nexpected_status = 200\nread_only_confirmed = true\n'
            f'expected_body_sha256 = "{hashlib.sha256(body.encode()).hexdigest()}"\n'
            for check, path, body in (
                ("static", "/healthz", bodies[0]),
                ("application", "/application", bodies[1]),
            )
        ),
        encoding="ascii",
    )
    policy = local / "policy.json"
    export(docker, controller_image, local, baked=baked)
    stage_files = [policy, collector_public]
    stage_files.extend(
        ROOT / "deploy" / "readonly" / name
        for name in ("install.py", "guard.py", "ssh_entry.py", "http_readiness.py")
    )
    for source in stage_files:
        docker("cp", str(source), f"{guest}:{STAGE}/{source.name}")
        execute("/usr/bin/chown", "0:0", f"{STAGE}/{source.name}")
        execute("/usr/bin/chmod", "0600", f"{STAGE}/{source.name}")
    execute(
        "/usr/bin/python3",
        "-I",
        f"{STAGE}/install.py",
        "--policy",
        f"{STAGE}/policy.json",
        "--public-key",
        f"{STAGE}/collector.pub",
    )
    stage(docker, guest, local, "sshd_config", SSHD)
    execute("/usr/sbin/sshd", "-f", f"{STAGE}/sshd_config")
    stage(docker, guest, local, "mode", "healthy")
    stage(
        docker,
        guest,
        local,
        "upstream.py",
        UPSTREAM.replace("EXPECTED_BODY", bodies[1]).replace("WRONG_BODY", bodies[2]),
    )
    docker("exec", "-d", guest, "/usr/bin/python3", "-I", f"{STAGE}/upstream.py")
    commands = json.loads(policy.read_bytes())["commands"]
    return {
        path: next(key for key, argv in commands.items() if argv[-3:-2] == [path])
        for path in ("/healthz", "/application")
    }


@dataclass
class Response:
    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return json.loads(self.body)


class Client:
    def __init__(self, address, port, token):
        self.address, self.port, self.token = address, port, token

    def request(self, method, path, *, payload=None, timeout=15, headers=None):
        with closing(http.client.HTTPConnection(self.address, self.port, timeout=timeout)) as conn:
            request_headers = {"Host": "127.0.0.1", "Authorization": f"Bearer {self.token}"}
            if payload is not None:
                request_headers["Content-Type"] = "application/json"
            request_headers.update(headers or {})
            conn.request(
                method, path, None if payload is None else json.dumps(payload), request_headers
            )
            reply = conn.getresponse()
            body = reply.read(16_385)
            require(len(body) <= 16_384, "Unexpectedly large fixture API response")
            return Response(reply.status, {k.lower(): v for k, v in reply.getheaders()}, body)

    def get(self, path, *, timeout=15):
        return self.request("GET", path, timeout=timeout)

    def post(self, path, *, json, headers=None):
        return self.request("POST", path, payload=json, headers=headers)


class ContainerClient(Client):
    def __init__(self, docker, guest, container_id, source_token_sha256):
        self.docker, self.guest = docker, guest
        self.container_id = container_id
        self.source_token_sha256 = source_token_sha256

    def invoke(self, kind, args):
        return json.loads(
            self.docker(
                "exec",
                self.guest,
                PYTHON_IMAGE,
                "-B",
                "/fixture-runner.py",
                "--fixture-exec",
                json.dumps([kind, args]),
            )
        )

    def request(self, method, path, *, payload=None, timeout=15, headers=None):
        response = self.invoke(
            "api",
            {
                "method": method,
                "path": path,
                "payload": payload,
                "timeout": timeout,
                "headers": headers,
            },
        )
        if response is None:
            raise ConnectionError("Fixture API loopback is not ready")
        code, received_headers, body = response
        return Response(code, received_headers, body.encode("latin-1"))

    def ssh(self, address, command, *, pinned="known_hosts"):
        code, stdout, stderr = self.invoke(
            "ssh",
            {
                "address": address,
                "command": command,
                "pinned": pinned,
            },
        )
        return subprocess.CompletedProcess(
            (), code, stdout.encode("latin-1"), stderr.encode("latin-1")
        )


def inside_ssh(address, command, pinned):
    import paramiko

    require(pinned in {"known_hosts", "wrong_known_hosts"}, "Unknown fixture trust record")
    with paramiko.SSHClient() as client:
        client.load_host_keys(f"/fixture/{pinned}")
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                address,
                username=ACCOUNT,
                key_filename="/fixture/collector",
                allow_agent=False,
                look_for_keys=False,
                timeout=3,
                auth_timeout=3,
                banner_timeout=3,
                channel_timeout=3,
            )
        except paramiko.BadHostKeyException:
            return 255, "", ""
        _, stdout, stderr = client.exec_command(command, timeout=7)
        output, errors = stdout.read(16_385), stderr.read(16_385)
        require(len(output) + len(errors) <= 16_384, "Unexpectedly large fixture SSH response")
        return stdout.channel.recv_exit_status(), output.decode("latin-1"), errors.decode("latin-1")


def inside_fixture(payload):
    require(Path("/.dockerenv").is_file(), "A Docker fixture guest is required")
    kind, args = json.loads(payload)
    if kind == "api":
        try:
            response = Client("127.0.0.1", 8010, os.environ["OPSARK_TOKEN"]).request(**args)
        except (OSError, http.client.HTTPException):
            return None
        return response.status_code, response.headers, response.body.decode("latin-1")
    if kind == "ssh":
        return inside_ssh(**args)
    require(kind == "seed-handoff" and args == {}, "Unknown fixture transport")
    return seed_handoff()


def seed_handoff():
    """Create synthetic approval and reconciliation records in the disposable controller only."""
    from opsark.baselines import scope_for
    from opsark.config import Settings, load_hosts
    from opsark.models import Report
    from opsark.patch_store import PatchStore
    from opsark.storage import ReportStore

    settings = Settings(
        data_dir=Path("/state"),
        inventory_path=Path("/fixture/inventory.toml"),
        token=os.environ["OPSARK_TOKEN"],
    )
    host = load_hosts(settings)[HOST].public
    report_id, job_id, plan_id = (secrets.token_hex(16) for _ in range(3))
    plan_digest, policy = (secrets.token_hex(32) for _ in range(2))
    scope = scope_for(host)
    ReportStore(settings.data_dir / "reports.sqlite3").save(
        Report(
            id=report_id,
            host_id=host.id,
            host_name="Synthetic fixture",
            scenario="web_502",
            source="ssh",
            created_at=datetime.now(UTC) - timedelta(minutes=1),
            status="inconclusive",
            title="Synthetic investigation",
            summary="Synthetic handoff fixture",
            facts=[],
            candidates=[],
            missing=[],
            evidence=[],
            next_steps=[],
            scope_hash=scope,
            target=host,
        )
    )
    patches = PatchStore(settings.data_dir / "patches.sqlite3")
    require(
        patches.register_submission(
            host.id,
            job_id,
            plan_id,
            plan_digest,
            1,
            host_scope=scope,
            policy_digest=policy,
            authorization="assisted",
        ),
        "Synthetic approval could not be seeded",
    )
    patches.mark_unknown(host.id, job_id, plan_id)
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
        current_host_scope=scope,
        current_policy_digest=policy,
    )
    audit = patches.get_handoff_audit(host.id, job_id)
    require(audit is not None and audit["reconciled_at"], "Synthetic reconciliation is missing")
    return report_id, job_id


@contextmanager
def controller(docker, cleanup, local, network, image, *, baked=False):
    data = local / "controller-data"
    data.mkdir(mode=0o700)
    entry = local / "controller.py"
    entry.write_text(CONTROLLER, encoding="ascii")
    token = secrets.token_urlsafe(32)
    env = {
        "OPSARK_TOKEN": token,
        "OPSARK_AI_MODEL": "fixture-model",
        "OPSARK_AI_KEY": secrets.token_urlsafe(32),
    }
    if image is not None:
        env.update(
            OPSARK_DATA_DIR="/state",
            OPSARK_INVENTORY="/fixture/inventory.toml",
            PYTHONPATH="/app/src" if baked else "/fixture-code/src",
        )
        mounts = () if baked else ("--mount", source_mount("src"), "--mount", source_mount("web"))
        guest = network + "-controller"
        container = docker(
            "run",
            "-d",
            "--name",
            guest,
            "--network",
            network,
            *LIMITS,
            *LOCKED,
            "--user",
            "0:0",
            "--workdir",
            "/app" if baked else "/fixture-code",
            *mounts,
            "--mount",
            f"type=bind,src={local},dst=/fixture,readonly",
            "--mount",
            f"type=bind,src={data},dst=/state",
            "--mount",
            f"type=bind,src={Path(__file__).resolve()},dst=/fixture-runner.py,readonly",
            *(item for key, value in env.items() for item in ("--env", f"{key}={value}")),
            "--entrypoint",
            PYTHON_IMAGE,
            image,
            "-B",
            "/fixture/controller.py",
        ).decode("ascii")
        cleanup.callback(docker, "rm", "-f", guest, allowed=False)
        require(re.fullmatch(r"[0-9a-f]{64}", container), "Fixture container identity is invalid")
        client = ContainerClient(
            docker, guest, container, hashlib.sha256(token.encode()).hexdigest()
        )
        try:
            await_controller(client)
        except TimeoutError:
            startup = data / "startup-failed"
            if startup.exists():
                kind = startup.read_text(encoding="ascii")
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", kind):
                    raise RuntimeError(f"Fixture controller startup failed ({kind})") from None
            state = docker("inspect", "--format", "{{.State.Status}}", guest)
            if state in (b"running", b"exited", b"dead"):
                stage_path = data / "startup-stage"
                stage = stage_path.read_text(encoding="ascii") if stage_path.exists() else "entry"
                if stage not in {"entry", "importing", "serving"}:
                    stage = "unknown"
                raise RuntimeError(
                    f"Fixture controller is {state.decode()} but not ready ({stage})"
                ) from None
            raise
        yield client, client.ssh, data
    else:
        env.update(
            OPSARK_DATA_DIR=str(data),
            OPSARK_INVENTORY=str(local / "inventory.toml"),
            PYTHONPATH=str(ROOT / "src"),
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            process = subprocess.Popen(  # noqa: S603 -- actual app with inherited bound loopback FD.
                [sys.executable, "-B", str(entry), str(listener.fileno())],
                cwd=ROOT,
                env={**ENV, **env},
                pass_fds=(listener.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                client = Client("127.0.0.1", listener.getsockname()[1], token)
                await_controller(client)

                def local_ssh(address, command, *, pinned="known_hosts"):
                    return ssh(address, local, command, pinned=pinned)

                yield client, local_ssh, data
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    require(not (data / "ai-contacted").exists(), "AI provider was contacted")


def await_controller(client):
    for _ in range(60):
        try:
            result = client.get("/api/ai/status", timeout=0.5)
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
            continue
        require(
            result.status_code == 200, f"Fixture startup API returned HTTP {result.status_code}"
        )
        require(result.json()["configured"], "The isolated AI trap was not configured")
        return
    raise TimeoutError("Fixture controller did not start")


def snapshot(data, *, exclude_handoff_receipts=False):
    history = {}
    for path in sorted(data.glob("*.sqlite3")):
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            lines = connection.iterdump()
            if exclude_handoff_receipts:
                lines = (
                    line for line in lines if not line.startswith('INSERT INTO "handoff_receipts"')
                )
            history[path.name] = hashlib.sha256("\n".join(lines).encode()).digest()
    require("reports.sqlite3" in history, "Private history database missing")
    return history


def check_state(client, raw_ssh, address, commands, *, mode):
    statuses = {
        "healthy": (200, "match", True, True),
        "failed": (502, "status_mismatch", False, None),
        "wrong-origin": (200, "body_mismatch", True, False),
    }
    code, outcome, status_matches, body_matches = statuses[mode]
    for path, expected in (
        ("/healthz", b"OPSARK_HTTP_READINESS_V1 200 match\n"),
        ("/application", f"OPSARK_HTTP_READINESS_V1 {code} {outcome}\n".encode()),
    ):
        result = raw_ssh(address, commands[path])
        require(
            result.returncode == 0 and result.stdout == expected and not result.stderr,
            f"SSH receipt failed in {mode} mode",
        )
    state = "passed" if mode == "healthy" else "failed"
    response = client.post(API, json={})
    require(
        response.status_code == 200
        and response.headers.get("cache-control") == "no-store"
        and response.json()
        == {
            "host_id": HOST,
            "status": state,
            "checks": [
                {
                    "id": "static",
                    "status": "passed",
                    "http_status": 200,
                    "status_matches": True,
                    "body_matches": True,
                },
                {
                    "id": "application",
                    "status": state,
                    "http_status": code,
                    "status_matches": status_matches,
                    "body_matches": body_matches,
                },
            ],
        },
        f"API status or data boundary failed in {mode} mode",
    )


def check_handoff(client, data, set_mode, private_values):
    report_id, job_id = client.invoke("seed-handoff", {})
    before = snapshot(data, exclude_handoff_receipts=True)
    path = f"/api/reports/{report_id}/handoff-rechecks"
    export = f"/api/reports/{report_id}/handoff"
    job = {"job_id": job_id}
    initial = client.get(export + "?" + urlencode(job))
    require(
        initial.status_code == 200 and "待验收".encode() in initial.body,
        "Unverified synthetic task must remain pending",
    )
    history, exports = [], []
    for mode, status, matched, label in (
        ("failed", "failed", 1, "复验未通过"),
        ("wrong-origin", "failed", 1, "复验未通过"),
        ("timeout", "pending", 1, "待验收"),
        ("healthy", "passed", 2, "登记业务复验通过"),
    ):
        set_mode(mode)
        response = client.post(path, json=job)
        require(
            response.status_code == 201, f"Handoff recheck returned HTTP {response.status_code}"
        )
        row = response.json()
        require(
            set(row) == {"id", "at", "status", "configured_checks", "matched_checks"}
            and re.fullmatch(r"br-[0-9a-f]{32}", row["id"])
            and (row["status"], row["configured_checks"], row["matched_checks"])
            == (status, 2, matched),
            "The bound recheck state is incorrect",
        )
        history.append(row)
        selection = export + "?" + urlencode({**job, "recheck_report_id": row["id"]})
        artifact = client.get(selection)
        require(
            artifact.status_code == 200
            and label.encode() in artifact.body
            and "查询原任务已核实结果".encode() in artifact.body
            and all(value not in artifact.body + response.body for value in private_values),
            "Customer handoff failed evidence or privacy checks",
        )
        exports.append((selection, artifact.body))

    readback = client.get(path + "?" + urlencode(job))
    require(
        readback.status_code == 200 and readback.json()["rechecks"] == history[::-1],
        "Older bound rechecks were not kept",
    )
    for selection, previous in exports:
        artifact = client.get(selection)
        require(
            artifact.status_code == 200 and artifact.body == previous,
            "An earlier handoff export changed",
        )
    detached = client.get("/api/reports/" + history[-1]["id"])
    require(detached.status_code == 404, "A receipt appeared as an investigation report")
    with closing(sqlite3.connect((data / "reports.sqlite3").as_uri() + "?mode=ro", uri=True)) as db:
        saved = db.execute(
            "SELECT payload FROM handoff_receipts WHERE report_id=? AND job_id=?",
            (report_id, job_id),
        ).fetchall()
    require(
        len(saved) == len(history)
        and all(value not in raw.encode() for (raw,) in saved for value in private_values)
        and snapshot(data, exclude_handoff_receipts=True) == before,
        "A recheck leaked response content or changed the original ledger or report",
    )
    report = client.get(f"/api/reports/{report_id}")
    require(
        report.status_code == 200 and report.json()["id"] == report_id, "Original report missing"
    )
    return {
        "report_id": report_id,
        "job_id": job_id,
        "history": readback.json()["rechecks"],
        "export_sha256": {
            row["id"]: hashlib.sha256(artifact).hexdigest()
            for row, (_, artifact) in zip(history, exports, strict=True)
        },
        "report_sha256": hashlib.sha256(report.body).hexdigest(),
        "source_token_sha256": client.source_token_sha256,
    }


def cold_sidecar(root, destination):
    sidecar = destination.with_name(destination.name + ".expected.json")
    require(
        destination.parent == root
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", destination.name)
        and not any(path.exists() or path.is_symlink() for path in (destination, sidecar)),
        "The cold snapshot and proof must be new direct children of the private laboratory",
    )
    return sidecar


def capture_cold_snapshot(docker, client, image, root, data, destination, expected):
    sidecar = cold_sidecar(root, destination)
    container = client.container_id
    inspect = (
        "inspect",
        "--type",
        "container",
        "--format",
        "{{.Id}} {{.Image}} {{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}",
        container,
    )
    require(
        docker(*inspect).decode("ascii").split() == [container, image, "running", "false", "0"],
        "The pinned fixture controller was not running before capture",
    )
    docker("stop", "--time", "5", container)
    final = docker(*inspect).decode("ascii").split()
    require(
        final
        in (
            [container, image, "exited", "false", "0"],
            [container, image, "exited", "false", "143"],
        )
        and not (data / "ai-contacted").exists(),
        "The fixture controller did not stop cleanly or the AI trap was contacted",
    )
    transfer = ["/usr/bin/python3", "-I", str(ROOT / "deploy/observer/store_transfer.py")]
    captured = json.loads(run([*transfer, "snapshot", str(data), str(destination)]).stdout)
    verified = json.loads(run([*transfer, "verify", str(destination)]).stdout)
    require(
        verified["status"] == captured["status"] == "complete"
        and verified["database_count"] == len(captured["databases"]) == 10
        and captured["databases"]["reports.sqlite3"]["table_rows"]["handoff_receipts"]
        == len(expected["history"]),
        "The cold manifest did not verify all ten stores and their handoff receipts",
    )
    descriptor = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(json.dumps(expected, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def exercise(root, ssh_image, nginx_image, controller_image, *, handoff=False, cold_snapshot=None):
    baked = cold_snapshot is not None
    if baked:
        require(handoff and controller_image is not None, "Cold capture requires a handoff image")
        cold_sidecar(root, cold_snapshot)
    with TemporaryDirectory(prefix="readiness-", dir=root) as temporary, ExitStack() as cleanup:
        local = Path(temporary)
        name = "opsark-" + local.name + "-" + secrets.token_hex(5)

        def docker(*args, allowed=True):
            command = [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "--config",
                str(local),
                *args,
            ]
            result = run(command, allowed=False)
            if allowed and result.returncode:
                operation = args[0]
                if operation == "exec":
                    if "/fixture-runner.py" in args:
                        transport, _ = json.loads(args[-1])
                        if transport in ("api", "ssh", "seed-handoff"):
                            operation = f"exec {transport}"
                    else:
                        for label in ("install.py", "sshd", "upstream.py", "ssh-keygen"):
                            if any(Path(item).name == label for item in args):
                                operation = f"exec {label}"
                                break
                kind = re.findall(rb"(?:^|\n)([A-Za-z_][A-Za-z0-9_]{0,79}):", result.stderr)
                detail = f" ({kind[-1].decode('ascii')})" if kind else ""
                raise RuntimeError(f"Fixture Docker {operation} failed{detail}")
            return result.stdout.strip()

        for image in {ssh_image, nginx_image, controller_image} - {None}:
            info = docker(
                "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
            )
            require(
                info.decode("ascii").split() in ([image, "null"], [image, "{}"]),
                "Fixture image must be pinned and declare no volumes",
            )
        docker("network", "create", "--internal", "--driver", "bridge", name)
        cleanup.callback(docker, "network", "rm", name, allowed=False)
        guest = name + "-ssh"
        docker(
            "run",
            "-d",
            "--name",
            guest,
            "--network",
            name,
            *LIMITS,
            "--entrypoint",
            "/bin/sleep",
            ssh_image,
            "infinity",
        )
        cleanup.callback(docker, "rm", "-f", guest, allowed=False)
        address = guest_address(docker, guest)
        bodies = tuple("synthetic-canary-" + secrets.token_hex(16) for _ in range(3))
        commands = prepare_guest(
            docker, guest, local, address, bodies, controller_image, baked=baked
        )

        nginx_config = local / "nginx.conf"
        nginx_config.write_text(NGINX.replace("STATIC_BODY", bodies[0]), encoding="ascii")
        nginx_config.chmod(0o644)
        nginx = name + "-nginx"
        docker(
            "run",
            "-d",
            "--name",
            nginx,
            "--network",
            f"container:{guest}",
            *LIMITS,
            *LOCKED,
            "--user",
            "65534:65534",
            "--tmpfs",
            "/run/opsark-nginx-live:rw,nosuid,nodev,noexec,size=2m,uid=65534,gid=65534",
            "--mount",
            f"type=bind,src={nginx_config},dst=/fixture.conf,readonly",
            "--entrypoint",
            "/usr/sbin/nginx",
            nginx_image,
            "-p",
            "/run/opsark-nginx-live",
            "-c",
            "/fixture.conf",
            "-e",
            "stderr",
        )
        cleanup.callback(docker, "rm", "-f", nginx, allowed=False)

        expected = None
        with controller(docker, cleanup, local, name, controller_image, baked=baked) as (
            client,
            raw_ssh,
            data,
        ):
            before = snapshot(data)
            denied = client.post(API, json={}, headers={"Authorization": ""})
            require(denied.status_code == 401, "Readiness route allowed an unauthenticated call")
            require(
                client.post(API, json={"path": "/wrong"}).status_code == 422,
                "Readiness route allowed a caller-supplied target",
            )
            command = commands["/application"]
            wrong_pin = raw_ssh(address, command, pinned="wrong_known_hosts")
            require(
                wrong_pin.returncode == 255 and not wrong_pin.stdout,
                "An incorrect SSH host key was accepted",
            )
            for modified in (command.replace("/application", "/unregistered"), command + " "):
                refused = raw_ssh(address, modified)
                require(
                    refused.returncode != 0
                    and not refused.stdout
                    and all(body.encode() not in refused.stderr for body in bodies),
                    "The forced command accepted modified argv or leaked a canary",
                )
            for mode in ("healthy", "failed", "wrong-origin", "healthy"):
                stage(docker, guest, local, "mode", mode)
                check_state(client, raw_ssh, address, commands, mode=mode)
            reports = client.get("/api/reports")
            require(
                reports.status_code == 200 and reports.json() == [] and snapshot(data) == before,
                "Readiness calls changed investigation history",
            )
            if handoff:
                require(
                    isinstance(client, ContainerClient),
                    "Handoff needs an isolated controller image",
                )
                expected = check_handoff(
                    client,
                    data,
                    lambda mode: stage(docker, guest, local, "mode", mode),
                    tuple(body.encode() for body in (*bodies, DOMAIN, "/application", "/healthz")),
                )
        if cold_snapshot is not None:
            require(expected is not None, "Cold capture requires a completed handoff")
            capture_cold_snapshot(
                docker, client, controller_image, root, data, cold_snapshot, expected
            )
    return {
        "real_pinned_ssh_and_exact_argv": True,
        "static_passed_throughout": True,
        "upstream_502_failed": True,
        "wrong_origin_200_failed": True,
        "restored_upstream_passed": True,
        "receipt_and_api_contained_no_body": True,
        "no_history_or_ai_side_effect": True,
        **({"cold_snapshot_captured": True} if baked else {}),
        **(
            {
                "real_handoff_502_wrong_200_timeout_and_recovery": True,
                "historical_exports_unchanged": True,
                "original_task_audit_seeded_and_unchanged": True,
            }
            if handoff
            else {}
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ssh-image", required=True)
    parser.add_argument("--nginx-image", required=True)
    parser.add_argument(
        "--controller-image", help="Pinned controller image (baked application for cold capture)"
    )
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    parser.add_argument("--handoff", action="store_true")
    parser.add_argument(
        "--cold-snapshot", type=Path, help="Capture the baked handoff test's ten stores"
    )
    args = parser.parse_args()
    try:
        require_root(args.root)
        require(
            all(
                re.fullmatch(r"sha256:[0-9a-f]{64}", image)
                for image in (args.ssh_image, args.nginx_image, args.controller_image)
                if image is not None
            ),
            "Use locally pinned image IDs",
        )
        outcome = exercise(
            args.root,
            args.ssh_image,
            args.nginx_image,
            args.controller_image,
            handoff=args.handoff,
            cold_snapshot=args.cold_snapshot,
        )
        print(json.dumps(outcome, sort_keys=True))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        StopIteration,
        sqlite3.Error,
        subprocess.SubprocessError,
        http.client.HTTPException,
    ):
        print("The isolated readiness fixture could not complete.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture-exec":
        try:
            print(json.dumps(inside_fixture(sys.argv[2])))
        except Exception as error:
            kind = type(error).__name__
            if kind.isascii() and kind.isidentifier():
                print(f"{kind}: isolated transport failed", file=sys.stderr)
            raise SystemExit(1) from None
        raise SystemExit(0)
    raise SystemExit(main())
