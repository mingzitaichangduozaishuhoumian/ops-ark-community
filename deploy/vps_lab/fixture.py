#!/usr/bin/python3
"""Administrator-only, fixed-name VPS fault fixture; never a collector command."""

import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

NAME = "opsark-lab-api"
IMAGE = "python:3.13-slim"
LABELS = {"io.opsark.fixture": "v1", "io.opsark.fixture.id": NAME}
NGINX_PORT = 18880
UPSTREAM_PORT = 18881
DOMAIN = "opsark-lab.invalid"
CONF = Path("/etc/nginx/conf.d/opsark-vps-lab.conf")
MARKER = "# OpsArk disposable VPS fixture v1: opsark-lab-api\n"
CONF_TEXT = (
    MARKER
    + """server {
    listen 127.0.0.1:18880;
    server_name opsark-lab.invalid;
    access_log off;
    error_log /var/log/nginx/error.log warn;
    location / {
        proxy_pass http://127.0.0.1:18881;
        proxy_connect_timeout 2s;
        proxy_read_timeout 3s;
    }
}
"""
)
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
INSPECT_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Config.Labels}},'
    '"State":{{json .State}},"RestartCount":{{.RestartCount}},'
    '"MemoryLimit":{{.HostConfig.Memory}},"Image":{{json .Image}}}'
)
HEALTHY_SCRIPT = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        normal = path in {'/', '/healthz', '/robots.txt', '/sitemap.xml', '/static/app.css'}
        code = 200 if normal else 503 if path == '/lab-error' else 404
        if normal:
            body = b'OPSARK_LAB_OK\\n'
        elif code == 503:
            body = b'OPSARK_LAB_CONTROLLED_ERROR\\n'
        else:
            body = b'Not found\\n'
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
    def do_POST(self):
        path = self.path.split('?', 1)[0]
        self.send_response(204 if path == '/callback' else 404)
        self.send_header('Content-Length', '0')
        self.end_headers()
HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()
"""
FAIL_SCRIPT = (
    "import sys,time; print('OPSARK_LAB_EXIT42_STDOUT',flush=True); "
    "print('OPSARK_LAB_EXIT42_STDERR',file=sys.stderr,flush=True); time.sleep(11); sys.exit(42)"
)
ACTIONS = {"init", "healthy", "start", "stop", "fail42", "status", "cleanup"}


class FixtureError(Exception):
    """A public error code, without daemon stderr or arbitrary command text."""


def environment():
    # Do not inherit user rc, proxy, Docker context, TLS or credential configuration.
    return {"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C", "HOME": "/root"}


def tool(name):
    executable = shutil.which(name, path=TRUSTED_PATH)
    if executable is None:
        raise FixtureError("required_tool_missing_" + name)
    return executable


def execute(argv, *, timeout=15):
    try:
        return subprocess.run(  # noqa: S603 -- fixed argv, no shell or caller-defined target.
            argv, capture_output=True, text=True, check=False, timeout=timeout, env=environment()
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FixtureError("fixed_command_did_not_complete") from error


def docker(*arguments, timeout=15):
    # An empty private config also avoids inheriting root's CLI proxies/credentials.
    with TemporaryDirectory(prefix="opsark-vps-docker-") as directory:
        return execute(
            [
                tool("docker"),
                "--config",
                directory,
                "--host",
                "unix:///var/run/docker.sock",
                *arguments,
            ],
            timeout=timeout,
        )


def require_root():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise FixtureError("administrator_root_required")


def require_linux_docker():
    result = docker("info", "--format", "{{.OSType}}")
    if result.returncode != 0 or result.stdout.strip() != "linux":
        raise FixtureError("local_linux_docker_unavailable")


def inspect_container():
    result = docker("container", "inspect", "--format", INSPECT_FORMAT, NAME)
    if result.returncode != 0:
        if "No such container" in result.stderr or "No such object" in result.stderr:
            return None
        raise FixtureError("container_inspection_failed")
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise FixtureError("container_inspection_invalid") from error
    if not isinstance(value, dict):
        raise FixtureError("container_inspection_invalid")
    return value


def owned_container(value):
    if value is None:
        return None
    labels = value.get("Labels")
    if (
        value.get("Name") != "/" + NAME
        or not isinstance(labels, dict)
        or any(labels.get(key) != expected for key, expected in LABELS.items())
        or not isinstance(value.get("Id"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["Id"])
    ):
        raise FixtureError("refusing_unowned_container")
    return value


def safe_configuration():
    """Return existing marker-owned bytes; refuse symlinks and writable ownership."""
    if CONF.is_symlink():
        raise FixtureError("refusing_unowned_nginx_configuration")
    if not CONF.exists():
        return None
    details = CONF.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_mode & 0o022
        or details.st_size > 8192
    ):
        raise FixtureError("refusing_unowned_nginx_configuration")
    content = CONF.read_bytes()
    if not content.startswith(MARKER.encode()):
        raise FixtureError("refusing_unowned_nginx_configuration")
    return content


def configuration_directory():
    for path in (CONF.parent, *CONF.parent.parents):
        details = path.stat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
        ):
            raise FixtureError("nginx_configuration_directory_not_trusted")


def write_new_configuration(content):
    configuration_directory()
    if CONF.exists() or CONF.is_symlink():
        raise FixtureError("refusing_to_overwrite_nginx_configuration")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(CONF, flags, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)


def check_nginx():
    result = execute([tool("nginx"), "-t"])
    if result.returncode != 0:
        raise FixtureError("nginx_syntax_check_failed_no_reload")


def reload_nginx():
    # This helper is never called before a successful syntax check by an action.
    result = execute([tool("nginx"), "-s", "reload"])
    if result.returncode != 0:
        raise FixtureError("nginx_reload_failed_verify_actual_state")


def port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def ensure_image():
    result = docker("image", "inspect", "--format", "{{.Id}}", IMAGE)
    if result.returncode == 0:
        return
    if "No such image" not in result.stderr and "No such object" not in result.stderr:
        raise FixtureError("fixture_image_inspection_failed")
    pulled = docker("pull", IMAGE, timeout=180)
    if pulled.returncode != 0:
        raise FixtureError("fixture_image_pull_failed")


def remove_container(value):
    owned = owned_container(value)
    if owned is None:
        return
    # Recheck current fixed name, then delete its verified immutable ID only.
    current = owned_container(inspect_container())
    if current is None or current["Id"] != owned["Id"]:
        raise FixtureError("fixture_container_changed_before_removal")
    result = docker("rm", "--force", current["Id"])
    if result.returncode != 0:
        raise FixtureError("fixture_container_removal_failed")


def replace_container(*, fail=False):
    current = owned_container(inspect_container())
    if current is None and not port_available(UPSTREAM_PORT):
        raise FixtureError("fixture_upstream_port_occupied")
    ensure_image()
    remove_container(current)
    arguments = [
        "run",
        "-d",
        "--name",
        NAME,
        "--label",
        "io.opsark.fixture=v1",
        "--label",
        "io.opsark.fixture.id=" + NAME,
        "--publish",
        "127.0.0.1:18881:8081",
        "--network",
        "bridge",
        "--memory",
        "64m",
        "--cpus",
        "0.25",
        "--pids-limit",
        "32",
        "--cap-drop",
        "ALL",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=1m",
        "--log-opt",
        "max-file=2",
        "--restart",
        "on-failure:2" if fail else "no",
        IMAGE,
        "python",
        "-B",
        "-u",
        "-c",
        FAIL_SCRIPT if fail else HEALTHY_SCRIPT,
    ]
    result = docker(*arguments)
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", result.stdout.strip()):
        raise FixtureError("fixture_container_start_failed")
    return {"mode": "fail42" if fail else "healthy", "container_id": result.stdout.strip()}


def probe(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(
            "GET", "/healthz", headers={"Host": DOMAIN, "Accept-Encoding": "identity"}
        )
        response = connection.getresponse()
        body = response.read(8193)
        complete = len(body) <= 8192
        return {
            "status": "observed",
            "http_status": response.status,
            "truncated": not complete,
            "healthy_marker": complete and body == b"OPSARK_LAB_OK\n",
            "expected_healthy": response.status == 200 and complete and body == b"OPSARK_LAB_OK\n",
        }
    except (OSError, http.client.HTTPException):
        return {"status": "unavailable", "expected_healthy": False}
    finally:
        connection.close()


def status_result():
    result = {"ok": True, "action": "status", "fixture": NAME, "container": None, "errors": []}
    try:
        container = owned_container(inspect_container())
        if container is not None:
            result["container"] = {
                key: container.get(key)
                for key in ("Id", "Name", "State", "RestartCount", "MemoryLimit", "Image")
            }
            result["upstream"] = probe(UPSTREAM_PORT)
        else:
            result["upstream"] = {"status": "not_configured", "expected_healthy": False}
    except FixtureError as error:
        result["ok"] = False
        result["errors"].append(str(error))
    try:
        configuration = safe_configuration()
        result["nginx_configuration"] = {
            "present": configuration is not None,
            "sha256": hashlib.sha256(configuration).hexdigest()
            if configuration is not None
            else None,
        }
        result["nginx"] = (
            probe(NGINX_PORT)
            if configuration is not None
            else {"status": "not_configured", "expected_healthy": False}
        )
    except FixtureError as error:
        result["ok"] = False
        result["errors"].append(str(error))
    upstream, nginx, container_value = (
        result.get("upstream"),
        result.get("nginx"),
        result.get("container"),
    )
    state = container_value.get("State") if isinstance(container_value, dict) else None
    result["fixture_healthy"] = bool(
        result["ok"]
        and isinstance(upstream, dict)
        and upstream.get("expected_healthy") is True
        and isinstance(nginx, dict)
        and nginx.get("expected_healthy") is True
        and isinstance(state, dict)
        and state.get("Status") == "running"
    )
    return result


def initialize():
    configuration_directory()
    configuration = safe_configuration()
    current = owned_container(inspect_container())
    if configuration is not None and configuration != CONF_TEXT.encode():
        raise FixtureError("owned_nginx_configuration_differs_refusing_overwrite")
    if configuration is None and not port_available(NGINX_PORT):
        raise FixtureError("fixture_nginx_port_occupied")
    if current is None and not port_available(UPSTREAM_PORT):
        raise FixtureError("fixture_upstream_port_occupied")
    created_configuration = configuration is None
    if created_configuration:
        write_new_configuration(CONF_TEXT.encode())
    try:
        check_nginx()
        replacement = replace_container()
    except FixtureError:
        if created_configuration and safe_configuration() is not None:
            CONF.unlink()
        raise
    reload_nginx()
    return {
        "ok": True,
        "action": "init",
        "fixture": NAME,
        **replacement,
        "nginx_reloaded": True,
        "business_recovery_verified": False,
    }


def cleanup():
    container = owned_container(inspect_container())
    configuration = safe_configuration()
    if configuration is not None:
        configuration_directory()
        CONF.unlink()
        try:
            check_nginx()
        except FixtureError:
            write_new_configuration(configuration)
            raise
        try:
            reload_nginx()
        except FixtureError:
            write_new_configuration(configuration)
            raise
    remove_container(container)
    return {
        "ok": True,
        "action": "cleanup",
        "fixture": NAME,
        "configuration_removed": configuration is not None,
        "container_removed": container is not None,
    }


def action(name):
    require_root()
    tool("docker")
    tool("nginx")
    if name == "status":
        return status_result()
    require_linux_docker()
    if name == "init":
        return initialize()
    if name == "cleanup":
        return cleanup()
    if name in {"healthy", "fail42"}:
        return {
            "ok": True,
            "action": name,
            "fixture": NAME,
            **replace_container(fail=name == "fail42"),
        }
    container = owned_container(inspect_container())
    if container is None:
        raise FixtureError("fixture_container_missing")
    result = docker(name, container["Id"])
    if result.returncode != 0:
        raise FixtureError("fixture_container_" + name + "_failed")
    return {"ok": True, "action": name, "fixture": NAME, "container_id": container["Id"]}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ACTIONS:
        print(
            json.dumps(
                {"ok": False, "error": "one_fixed_action_required", "actions": sorted(ACTIONS)}
            )
        )
        return 2
    try:
        result = action(sys.argv[1])
    except (FixtureError, OSError, ValueError) as error:
        code = (
            str(error) if isinstance(error, FixtureError) else "fixture_operation_did_not_complete"
        )
        result = {"ok": False, "action": sys.argv[1], "fixture": NAME, "error": code}
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        raise SystemExit(main())
