"""Provision an isolated first-use SSH wizard lab in explicit resumable phases."""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LAB = Path("/var/lib/opsark-release-lab")
LABEL = "io.opsark.onboarding-lab"
HOST = "beginner-web"
TARGET = "198.18.242.2"
CONTROLLER = "198.18.242.3"
UID = 10001
PYTHON = "/app/.venv/bin/python"
REMOTE = "/run/opsark-onboarding"
KEY = f"ssh/opsark-{HOST}-readonly"
KNOWN = f"ssh/opsark-{HOST}-known-hosts"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
SHA = re.compile(r"sha256:[0-9a-f]{64}")
CID = re.compile(r"[0-9a-f]{64}")
LIMITS = (
    "--pull",
    "never",
    "--pids-limit",
    "64",
    "--memory",
    "192m",
    "--memory-swap",
    "192m",
    "--cpus",
    "0.5",
    "--log-driver",
    "none",
    "--no-healthcheck",
)
REAPER = """import os,signal,time
def stop(*_args): raise SystemExit
signal.signal(signal.SIGTERM,stop)
deadline=time.monotonic()+1800
while time.monotonic()<deadline:
    while True:
        try:
            if os.waitpid(-1,os.WNOHANG)[0]==0: break
        except ChildProcessError: break
    time.sleep(.05)
"""
TARGET_SCRIPT = r"""import http.client,json,os,select,signal,subprocess,sys,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path

HERE=Path('/run/opsark-onboarding')
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_args): pass
    def do_GET(self):
        body=b'OPSARK_ONBOARDING_UPSTREAM_OK\n'
        self.send_response(200); self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)

def ticks(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19])

def get(host):
    c=http.client.HTTPConnection('127.0.0.1',8080,timeout=1)
    c.request('GET','/healthz',headers={'Host':host})
    r=c.getresponse(); status=r.status; r.read(2048); c.close(); return status

if sys.argv[1:]==['_upstream']:
    HTTPServer(('127.0.0.1',8081),Handler).serve_forever()
elif sys.argv[1:]==['start']:
    child=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__)),'_upstream'],
                           stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    proof={'pid':child.pid,'ticks':ticks(child.pid),'net':os.stat('/proc/self/ns/net').st_ino}
    fd=os.open(HERE/'upstream.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: json.dump(proof,f)
    subprocess.Popen(['/usr/sbin/sshd','-D','-f',str(HERE/'sshd.conf')],
                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.Popen(['/usr/sbin/nginx','-e','/var/log/nginx/error.log','-c',str(HERE/'nginx.conf')],
                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if get('shop.opsark.invalid')==200 and get('blog.opsark.invalid')==200: break
        except OSError: pass
        time.sleep(.1)
    else: raise RuntimeError('startup')
    print('ready')
elif sys.argv[1:]==['fault']:
    path=HERE/'upstream.json'
    if path.exists():
        p=json.loads(path.read_text()); pid=p['pid']; descriptor=os.pidfd_open(pid,0)
        try:
            assert ticks(pid)==p['ticks'] and os.stat(f'/proc/{pid}/ns/net').st_ino==p['net']
            assert os.path.samestat(os.stat(f'/proc/{pid}/ns/net'),os.stat('/proc/self/ns/net'))
            assert Path(f'/proc/{pid}/exe').resolve()==Path(sys.executable).resolve()
            assert Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]==[
                os.fsencode(sys.executable),b'-I',b'-B',os.fsencode(__file__),b'_upstream']
            signal.pidfd_send_signal(descriptor,signal.SIGTERM)
            assert select.select([descriptor],[],[],3)[0]
        finally: os.close(descriptor)
        path.unlink()
    assert get('shop.opsark.invalid')==502 and get('blog.opsark.invalid')==200
    assert b'connect() failed' in Path('/var/log/nginx/error.log').read_bytes()[-8192:]
    print('fault-confirmed')
else: raise SystemExit(2)
"""
SSHD = f"""Port 22
ListenAddress {TARGET}
HostKey {REMOTE}/host-key
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM yes
AllowUsers opsark-readonly
AuthorizedKeysFile .ssh/authorized_keys
DisableForwarding yes
PermitTTY no
LogLevel QUIET
"""
NGINX = f"""daemon off;
master_process off;
user root;
pid {REMOTE}/nginx.pid;
error_log /var/log/nginx/error.log notice;
events {{ worker_connections 32; }}
http {{
    access_log off;
    client_body_temp_path {REMOTE}/body;
    proxy_temp_path {REMOTE}/proxy;
    fastcgi_temp_path {REMOTE}/fastcgi;
    uwsgi_temp_path {REMOTE}/uwsgi;
    scgi_temp_path {REMOTE}/scgi;
    server {{ listen 8080 default_server; return 404; }}
    server {{
        listen 8080;
        server_name shop.opsark.invalid;
        location = /healthz {{ proxy_connect_timeout 1s; proxy_pass http://127.0.0.1:8081; }}
        location / {{ return 404; }}
    }}
    server {{
        listen 8080;
        server_name blog.opsark.invalid;
        location = /healthz {{ return 200 "OPSARK_ONBOARDING_CONTROL_OK\\n"; }}
        location / {{ return 404; }}
    }}
}}
"""
READY = """import http.client,time
from contextlib import closing
deadline=time.monotonic()+30
while time.monotonic()<deadline:
    try:
        with closing(http.client.HTTPConnection('127.0.0.1',8010,timeout=.5)) as c:
            c.request('GET','/api/status'); r=c.getresponse(); r.read(4096)
        if r.status==200: print('ready'); break
    except (OSError,http.client.HTTPException): pass
    time.sleep(.1)
else: raise SystemExit(1)
"""


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def run(arguments, detail, *, timeout=20):
    result = subprocess.run(  # noqa: S603 -- fixed private fixture argv, no shell.
        arguments,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=timeout,
        check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= 65_536, detail)
    return result.stdout.strip()


def private_read(path, *, uid=0, limit=16_384):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == uid
            and info.st_nlink == 1
            and not info.st_mode & 0o077
            and 0 <= info.st_size <= limit,
            "The isolated fixture file is not private",
        )
        result = handle.read(limit + 1)
        require(len(result) == info.st_size, "The isolated fixture file changed while reading")
        return result


def write(path, data, *, uid=0):
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(5))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, uid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def trusted_root(path):
    require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and path.is_absolute()
        and path.resolve() == path
        and path != LAB
        and path.is_relative_to(LAB),
        "A private authorized Linux fixture stage is required",
    )
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "The fixture stage is not administrator-owned",
        )
    require(not path.stat().st_mode & 0o077, "The fixture stage must be private")


class Lab:
    def __init__(self, root):
        trusted_root(root)
        self.root = root
        self.state_path = root / "onboarding-state.json"
        self.cfg = root / "onboarding-config"
        self.data = root / "onboarding-data"
        self.install = root / "onboarding-install"
        self.state: dict[str, Any] = (
            json.loads(private_read(self.state_path)) if self.state_path.exists() else {}
        )
        require(isinstance(self.state, dict), "Invalid private fixture state")
        if self.state:
            require(
                set(self.state)
                == {
                    "nonce",
                    "network",
                    "target",
                    "controller",
                    "phase",
                    "image",
                    "controller_image",
                }
                and re.fullmatch(r"[0-9a-f]{20}", self.state["nonce"]),
                "Invalid private fixture state",
            )

    def save(self):
        write(self.state_path, json.dumps(self.state, sort_keys=True).encode("ascii"))

    def docker(self, *args, timeout=20):
        return run(
            [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "--config",
                str(self.install),
                *args,
            ],
            "Isolated Docker " + args[0] + " failed",
            timeout=timeout,
        )

    def resource(self, role):
        require(self.state, "Prepare the isolated fixture first")
        recorded = self.state[role]
        require(
            isinstance(recorded, dict)
            and set(recorded) == {"name", "id"}
            and recorded["name"] == "opsark-onboarding-" + self.state["nonce"] + "-" + role,
            "The fixture resource scope differs",
        )
        kind = "network" if role == "network" else "container"
        observed = json.loads(self.docker(kind, "inspect", recorded["id"] or recorded["name"]))
        require(isinstance(observed, list) and len(observed) == 1, "Fixture resource absent")
        observed = observed[0]
        labels = (
            observed.get("Labels", {})
            if role == "network"
            else observed["Config"].get("Labels", {})
        )
        require(
            labels.get(LABEL) == self.state["nonce"]
            and observed["Name"].lstrip("/") == recorded["name"]
            and CID.fullmatch(observed["Id"])
            and (not recorded["id"] or observed["Id"] == recorded["id"]),
            "Fixture ownership differs",
        )
        if role == "network":
            require(
                observed["Internal"] is True
                and observed["Driver"] == "bridge"
                and len(observed["IPAM"]["Config"]) == 1
                and observed["IPAM"]["Config"][0]["Subnet"] == "198.18.242.0/28",
                "The fixture network is outside the isolated subnet",
            )
        else:
            network_name = self.state["network"]["name"]
            interfaces = observed["NetworkSettings"]["Networks"]
            require(
                observed["HostConfig"]["Privileged"] is False
                and observed["HostConfig"]["NetworkMode"] == self.state["network"]["id"]
                and observed["HostConfig"]["PortBindings"] in (None, {})
                and set(interfaces) == {network_name},
                "The fixture network exposure differs",
            )
            if observed["State"]["Running"]:
                require(
                    interfaces[network_name]["IPAddress"]
                    == (TARGET if role == "target" else CONTROLLER),
                    "The fixture private address differs",
                )
            if role == "controller":
                require(
                    observed["HostConfig"]["ReadonlyRootfs"] is True
                    and observed["Config"]["User"] == f"{UID}:{UID}"
                    and len(observed["Mounts"]) == 2
                    and {
                        (row["Source"], row["Destination"], row["RW"]) for row in observed["Mounts"]
                    }
                    == {
                        (str(self.cfg), "/enrollment", False),
                        (str(self.data), "/app/data", True),
                    },
                    "The controller has unexpected access",
                )
            else:
                require(observed["Mounts"] == [], "The test target has an unexpected host mount")
        return observed

    def execute(self, role, *arguments):
        identity = self.resource(role)["Id"]
        return self.docker("exec", identity, *arguments)

    def copy(self, role, source, destination):
        identity = self.resource(role)["Id"]
        require(
            destination.startswith(REMOTE + "/") and ".." not in Path(destination).parts,
            "Invalid target staging destination",
        )
        self.docker("cp", str(source), identity + ":" + destination)
        self.execute(role, "/usr/bin/chown", "0:0", destination)
        self.execute(role, "/usr/bin/chmod", "0600", destination)

    def image(self, image):
        require(SHA.fullmatch(image), "Use a pinned local fixture image")
        metadata = self.docker(
            "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
        )
        require(
            metadata.decode().split() in ([image, "null"], [image, "{}"]),
            "The pinned fixture image must declare no volumes",
        )

    def create(self, role, image, *args, command=()):
        require(not self.state[role]["id"], "The fixture container already exists")
        network = self.resource("network")["Id"]
        address = TARGET if role == "target" else CONTROLLER
        identity = self.docker(
            "create",
            "--name",
            self.state[role]["name"],
            "--label",
            LABEL + "=" + self.state["nonce"],
            "--network",
            network,
            "--ip",
            address,
            *LIMITS,
            *args,
            image,
            *command,
        )
        require(CID.fullmatch(identity.decode()), "The created fixture identity is invalid")
        self.state[role]["id"] = identity.decode()
        self.save()
        self.docker("start", identity.decode())

    def controller_ready(self):
        controller = self.resource("controller")
        require(
            controller["State"]["Running"] is True and controller["State"]["OOMKilled"] is False,
            "The owned controller is stopped or has an OOM result",
        )
        try:
            reply = self.docker(
                "exec", controller["Id"], PYTHON, "-I", "-B", "-c", READY, timeout=35
            )
        finally:
            current = self.resource("controller")
            require(
                current["State"]["Running"] is True and current["State"]["OOMKilled"] is False,
                "The owned controller stopped or recorded an OOM result during readiness",
            )
        require(reply == b"ready", "The private controller was not ready")

    def prepare(self, image, controller_image):
        require(not self.state, "The fixture was already prepared")
        for directory in (self.cfg, self.data, self.install):
            directory.mkdir(mode=0o700)
        nonce = secrets.token_hex(10)
        self.state = {
            "nonce": nonce,
            "phase": "preparing",
            "image": image,
            "controller_image": controller_image,
        }
        for role in ("network", "target", "controller"):
            self.state[role] = {"name": "opsark-onboarding-" + nonce + "-" + role, "id": ""}
        self.save()
        self.image(image)
        self.image(controller_image)
        network = self.docker(
            "network",
            "create",
            "--internal",
            "--driver",
            "bridge",
            "--subnet",
            "198.18.242.0/28",
            "--label",
            LABEL + "=" + nonce,
            self.state["network"]["name"],
        ).decode()
        require(CID.fullmatch(network), "The created internal network identity is invalid")
        self.state["network"]["id"] = network
        self.save()
        self.create(
            "target",
            image,
            "--user",
            "0:0",
            "--entrypoint",
            "/usr/bin/python3",
            command=("-I", "-B", "-c", REAPER),
        )
        self.execute("target", "/usr/bin/install", "-d", "-m", "0700", REMOTE)
        self.execute(
            "target", "/usr/bin/install", "-d", "-m", "0755", "/run/sshd", "/var/log/nginx"
        )
        self.execute(
            "target",
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            "from pathlib import Path; p=Path('/var/log/nginx/error.log'); "
            "p.unlink(missing_ok=True); p.touch(mode=0o600)",
        )
        self.execute(
            "target",
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            REMOTE + "/host-key",
        )
        for name, contents in (
            ("target.py", TARGET_SCRIPT),
            ("sshd.conf", SSHD),
            ("nginx.conf", NGINX),
        ):
            source = self.install / name
            write(source, contents.encode("ascii"))
            self.copy("target", source, REMOTE + "/" + name)
        self.execute("target", "/usr/bin/python3", "-I", "-B", REMOTE + "/target.py", "start")
        raw = (
            self.execute("target", "/usr/bin/cat", REMOTE + "/host-key.pub").decode("ascii").split()
        )
        require(len(raw) >= 2 and raw[0] == "ssh-ed25519", "Invalid public target host key")
        host_key = " ".join(raw[:2])
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(raw[1], validate=True)).digest()
        ).decode().rstrip("=")
        (self.cfg / "ssh").mkdir(mode=0o700)
        run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.cfg / KEY)],
            "Dedicated synthetic collector key generation failed",
        )
        write(self.cfg / "inventory.toml", b"", uid=UID)
        for path in (
            self.cfg / KEY,
            self.cfg / (KEY + ".pub"),
            self.cfg / "ssh",
            self.cfg,
            self.data,
        ):
            os.chown(path, UID, UID)
            path.chmod(0o700 if path.is_dir() else 0o600)
        environment = {
            "OPSARK_DATA_DIR": "/app/data",
            "OPSARK_INVENTORY": "/enrollment/inventory.toml",
            "OPSARK_TOKEN": "",
            "OPSARK_AI_PROVIDER": "openai",
            "OPSARK_AI_BASE_URL": "",
            "OPSARK_AI_MODEL": "",
            "OPSARK_AI_KEY": "",
            "OPSARK_AI_KEY_FILE": "",
            "OPSARK_PATCH_INVENTORY": "",
            "OPSARK_AUTOMATION_POLICY": "",
            "OPSARK_OBSERVE_ENABLED": "0",
            "OPSARK_WEB_OBSERVE_ENABLED": "0",
            "OPSARK_VULNERABILITY_SCAN_ENABLED": "0",
            "OPSARK_VULNERABILITY_WEBHOOK_URL": "",
            "OPSARK_VULNERABILITY_WEBHOOK_KEY_FILE": "",
        }
        self.create(
            "controller",
            controller_image,
            "--read-only",
            "--user",
            f"{UID}:{UID}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,src={self.cfg},dst=/enrollment,readonly",
            "--mount",
            f"type=bind,src={self.data},dst=/app/data",
            *(part for key, value in environment.items() for part in ("--env", key + "=" + value)),
            "--entrypoint",
            PYTHON,
            command=(
                "-I",
                "-B",
                "-m",
                "uvicorn",
                "opsark.main:app",
                "--app-dir",
                "/app/src",
                "--host",
                "0.0.0.0",  # noqa: S104 -- private bridge listener without published ports.
                "--port",
                "8010",
                "--no-access-log",
            ),  # noqa: S104 -- private bridge.
        )
        self.controller_ready()
        token = private_read(self.data / "access-token", uid=UID, limit=256).decode("ascii").strip()
        require(len(token) >= 32, "The fresh synthetic token was not generated")
        descriptor = {
            "token": token,
            "controller_address": CONTROLLER,
            "controller_port": 8010,
            "target": {
                "host_id": HOST,
                "name": "First-use isolated VPS",
                "address": TARGET,
                "port": 22,
                "username": "opsark-readonly",
                "site_domain": "shop.opsark.invalid",
                "container_name": "api",
                "expected_upstream_port": 8081,
                "host_key": host_key,
                "expected_fingerprint": fingerprint,
            },
            "canaries": [],
        }
        write(self.root / "browser.private.json", json.dumps(descriptor).encode("ascii"))
        self.state["phase"] = "prepared"
        self.save()

    def activate(self):
        require(
            self.state and self.state["phase"] in {"prepared", "activated"},
            "The browser enrollment is not ready for activation",
        )
        descriptor = json.loads(private_read(self.root / "browser.private.json"))
        materials = json.loads(private_read(self.root / "materials.json"))
        require(
            set(materials)
            == {
                "host_id",
                "address",
                "port",
                "fingerprint",
                "inventory",
                "known_hosts",
                "key_file",
                "known_hosts_file",
                "known_hosts_digests",
            },
            "Unexpected browser materials",
        )
        target = descriptor["target"]
        expected = {
            key: target[key]
            for key in (
                "name",
                "address",
                "port",
                "username",
                "site_domain",
                "container_name",
                "expected_upstream_port",
            )
        }
        expected.update(id=HOST, credential="readonly-" + HOST)
        require(
            materials["host_id"] == HOST
            and materials["address"] == TARGET
            and materials["port"] == 22
            and materials["key_file"] == KEY
            and materials["known_hosts_file"] == KNOWN
            and materials["fingerprint"] == target["expected_fingerprint"]
            and isinstance(materials["inventory"], str)
            and len(materials["inventory"]) <= 8192,
            "Browser enrollment differs from the approved isolated target",
        )
        parsed = tomllib.loads(materials["inventory"])
        require(
            parsed
            == {
                "credentials": {"readonly-" + HOST: {"key_file": KEY, "known_hosts_file": KNOWN}},
                "hosts": [expected],
            },
            "Browser inventory introduced unapproved paths or fields",
        )
        known = TARGET + " " + target["host_key"] + "\n"
        require(
            materials["known_hosts"] == known
            and materials["known_hosts_digests"]
            == {
                "lf": hashlib.sha256(known.encode()).hexdigest(),
                "crlf": hashlib.sha256(known.replace("\n", "\r\n").encode()).hexdigest(),
                "no_final_newline": hashlib.sha256(known.rstrip("\n").encode()).hexdigest(),
            },
            "Browser public host pin differs from the independently trusted key",
        )
        write(self.cfg / KNOWN, known.encode("ascii"), uid=UID)
        write(self.cfg / "inventory.toml", materials["inventory"].encode("utf-8"), uid=UID)
        source = ROOT / "deploy/readonly"
        output = self.install / "export"
        output.mkdir(mode=0o700, exist_ok=True)
        os.chown(output, UID, UID)
        code = self.install / "export-code"
        code.mkdir(mode=0o755, exist_ok=True)
        code.chmod(0o755)
        write(code / "export_policy.py", (source / "export_policy.py").read_bytes())
        (code / "export_policy.py").chmod(0o644)
        self.docker(
            "run",
            "--rm",
            "--network",
            "none",
            *LIMITS,
            "--read-only",
            "--user",
            f"{UID}:{UID}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,src={code},dst=/fixture-code/deploy/readonly,readonly",
            "--mount",
            f"type=bind,src={self.cfg},dst=/enrollment,readonly",
            "--mount",
            f"type=bind,src={output},dst=/output",
            "--entrypoint",
            PYTHON,
            self.state["controller_image"],
            "-I",
            "-B",
            "-c",
            "import runpy,sys;sys.path.insert(0,'/app/src');"
            "runpy.run_path('/fixture-code/deploy/readonly/export_policy.py',run_name='__main__')",
            "--inventory",
            "/enrollment/inventory.toml",
            "--host-id",
            HOST,
            "--output",
            "/output/policy.json",
        )
        self.execute("target", "/usr/bin/install", "-d", "-m", "0700", REMOTE + "/readonly")
        for path in (
            source / "install.py",
            source / "guard.py",
            source / "ssh_entry.py",
            source / "http_readiness.py",
            output / "policy.json",
            self.cfg / (KEY + ".pub"),
        ):
            name = "collector.pub" if path == self.cfg / (KEY + ".pub") else path.name
            self.copy("target", path, REMOTE + "/readonly/" + name)
        self.execute(
            "target",
            "/usr/bin/python3",
            "-I",
            "-B",
            REMOTE + "/readonly/install.py",
            "--policy",
            REMOTE + "/readonly/policy.json",
            "--public-key",
            REMOTE + "/readonly/collector.pub",
        )
        self.restart()
        self.state["phase"] = "activated"
        self.save()

    def restart(self):
        identity = self.resource("controller")["Id"]
        self.docker("restart", "-t", "5", identity)
        self.controller_ready()

    def fault(self):
        require(
            self.state and self.state["phase"] in {"activated", "faulted"},
            "Activate the dedicated readonly enrollment first",
        )
        require(
            self.execute("target", "/usr/bin/python3", "-I", "-B", REMOTE + "/target.py", "fault")
            == b"fault-confirmed",
            "The actual upstream fault was not confirmed",
        )
        self.state["phase"] = "faulted"
        self.save()

    def guard_check(self):
        require(
            self.state and self.state["phase"] in {"activated", "faulted"},
            "Activate the dedicated readonly enrollment first",
        )
        self.resource("target")
        before = private_read(self.state_path)
        absent = (
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            "import os; raise SystemExit(int(os.path.lexists('/run/opsark-onboarding/forbidden')))",
        )
        self.execute("target", *absent)
        arguments = [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-oBatchMode=yes",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=none",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oStrictHostKeyChecking=yes",
            "-oUpdateHostKeys=no",
            "-oPreferredAuthentications=publickey",
            "-oConnectionAttempts=1",
            "-oConnectTimeout=3",
            "-oLogLevel=ERROR",
            "-oUserKnownHostsFile=" + str(self.cfg / KNOWN),
            "-i",
            str(self.cfg / KEY),
            "-p",
            "22",
            "opsark-readonly@" + TARGET,
        ]

        def ssh(command):
            result = subprocess.run(  # noqa: S603 -- pinned synthetic identity and literal SSH requests.
                [*arguments, command],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
                env=ENV,
            )
            require(
                len(result.stdout) + len(result.stderr) <= 8192,
                "The readonly SSH receipt exceeded its bound",
            )
            return result

        accepted = ssh("LC_ALL=C timeout -k 1s 5s cat /etc/os-release")
        require(
            accepted.returncode == 0
            and not accepted.stderr
            and any(
                line in (b"ID=ubuntu", b'ID="ubuntu"') for line in accepted.stdout.splitlines()
            ),
            "The registered readonly SSH command did not execute on the actual Ubuntu target",
        )
        for command in ("id", "touch /run/opsark-onboarding/forbidden"):
            denied = ssh(command)
            require(
                denied.returncode == 126
                and not denied.stdout
                and denied.stderr == b"OpsArk restricted collector refused this request.\n",
                "The target did not reject the unregistered command through its readonly guard",
            )
        self.execute("target", *absent)
        require(
            private_read(self.state_path) == before,
            "The readonly guard check changed fixture state",
        )
        return {
            "registered_ssh_command_executed": True,
            "arbitrary_ssh_commands_rejected": True,
            "forbidden_marker_absent": True,
        }

    def cleanup(self):
        require(self.state, "No owned onboarding fixture exists")
        if self.state["phase"] == "cleaned":
            return
        for role in ("controller", "target", "network"):
            if not self.state[role]["id"]:
                continue
            observed = self.resource(role)
            operation = ("network", "rm") if role == "network" else ("rm", "-f")
            self.docker(*operation, observed["Id"])
            self.state[role]["id"] = ""
            self.save()
        self.state["phase"] = "cleaned"
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--controller-image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    parser.add_argument(
        "phase", choices=("prepare", "activate", "fault", "restart", "guard-check", "cleanup")
    )
    args = parser.parse_args()
    try:
        require(
            SHA.fullmatch(args.image) and SHA.fullmatch(args.controller_image),
            "Use pinned local image IDs",
        )
        lab = Lab(args.root)
        extra = {}
        if args.phase == "prepare":
            lab.prepare(args.image, args.controller_image)
        else:
            require(
                lab.state
                and lab.state["image"] == args.image
                and lab.state["controller_image"] == args.controller_image,
                "The recorded image scope differs",
            )
            extra = getattr(lab, args.phase.replace("-", "_"))() or {}
        print(
            json.dumps(
                {"phase": args.phase, "completed": True, "isolated": True, **extra}, sort_keys=True
            )
        )
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError):
        print("The isolated onboarding phase could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
