"""Run actual Nginx and a fixed Python upstream in the disposable filesystem lab."""

import argparse
import importlib.util
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

STATE = Path("/fixture-state")
CONFIG = STATE / "mixed-nginx.conf"
ERROR_LOG = Path("/fixture-root/var/log/nginx/error.log")
TARGET_BODY = b"OPSARK_MIXED_TARGET_OK\n"
CONTROL_BODY = b"OPSARK_MIXED_CONTROL_OK\n"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
NGINX = "/usr/sbin/nginx"
CONFIGURATION = b"""daemon off;
master_process off;
user root;
pid /fixture-state/mixed-nginx.native.pid;
error_log /fixture-root/var/log/nginx/error.log notice;
events { worker_connections 32; }
http {
    access_log off;
    client_body_temp_path /fixture-state/client-body;
    proxy_temp_path /fixture-state/proxy;
    fastcgi_temp_path /fixture-state/fastcgi;
    uwsgi_temp_path /fixture-state/uwsgi;
    scgi_temp_path /fixture-state/scgi;
    server { listen 127.0.0.1:18080 default_server; return 404; }
    server {
        listen 127.0.0.1:18080;
        server_name shop.opsark.invalid;
        location = /healthz {
            proxy_connect_timeout 500ms;
            proxy_read_timeout 1s;
            proxy_next_upstream off;
            proxy_pass http://127.0.0.1:18081/healthz;
        }
        location / { return 404; }
    }
    server {
        listen 127.0.0.1:18080;
        server_name blog.opsark.invalid;
        location = /healthz { default_type text/plain; return 200 "OPSARK_MIXED_CONTROL_OK\\n"; }
        location / { return 404; }
    }
}
"""


def require(condition):
    if not condition:
        raise RuntimeError("The controlled mixed-fault fixture could not be verified")


def filesystem():
    spec = importlib.util.spec_from_file_location("filesystem_target", STATE / "target.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("The fixed filesystem helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.initialized(web_profile=True)
    require(module._inode_profile())
    return module


def _proof_path(kind):
    require(kind in {"nginx", "upstream"})
    return STATE / ("mixed-" + kind + ".json")


def _start_ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[19])


def _namespace(name, pid="self"):
    info = Path(f"/proc/{pid}/ns/{name}").stat()
    return [info.st_dev, info.st_ino]


def _process(kind):
    path = _proof_path(kind)
    if not path.exists():
        return None
    helper = filesystem()
    proof = json.loads(helper._read(path))
    require(
        set(proof) == {"pid", "started", "net", "mount"}
        and type(proof["pid"]) is int
        and proof["pid"] > 1
        and type(proof["started"]) is int
        and proof["started"] > 0
    )
    pid = proof["pid"]
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    try:
        require(
            _start_ticks(pid) == proof["started"]
            and _namespace("net", pid) == proof["net"] == _namespace("net")
            and _namespace("mnt", pid) == proof["mount"] == _namespace("mnt")
            and Path(f"/proc/{pid}/exe").resolve()
            == Path(
                NGINX if kind == "nginx" else sys.executable,
            ).resolve()
        )
        if kind == "upstream":
            require(
                Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")[:-1]
                == [
                    os.fsencode(sys.executable),
                    b"-I",
                    b"-B",
                    os.fsencode(Path(__file__).resolve()),
                    b"_upstream",
                ]
            )
        return descriptor, pid
    except BaseException:
        os.close(descriptor)
        raise


def _listening(pid, port):
    endpoint = socket.inet_aton("127.0.0.1")[::-1].hex().upper() + f":{port:04X}"
    rows = [
        fields
        for line in Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        if (fields := line.split())[3] == "0A" and fields[1] == endpoint
    ]
    if len(rows) != 1:
        return False
    wanted = "socket:[" + rows[0][9] + "]"
    for path in Path(f"/proc/{pid}/fd").iterdir():
        with suppress(FileNotFoundError):
            if os.readlink(path) == wanted:
                return True
    return False


def _stop(kind):
    owned = _process(kind)
    if owned is not None:
        descriptor, _ = owned
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            require(bool(select.select([descriptor], [], [], 3)[0]))
        finally:
            os.close(descriptor)
    _proof_path(kind).unlink(missing_ok=True)


def _start(kind):
    current = _process(kind)
    if current is not None:
        os.close(current[0])
        return
    path = _proof_path(kind)
    require(not path.exists())
    helper = filesystem()
    arguments = (
        [NGINX, "-e", str(ERROR_LOG), "-p", str(STATE), "-c", str(CONFIG)]
        if kind == "nginx"
        else [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_upstream"]
    )
    child = subprocess.Popen(  # noqa: S603 -- fixed immutable nginx or exact owned Python helper.
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=ENV,
        start_new_session=True,
    )
    try:
        helper._write(
            path,
            json.dumps(
                {
                    "pid": child.pid,
                    "started": _start_ticks(child.pid),
                    "net": _namespace("net", child.pid),
                    "mount": _namespace("mnt", child.pid),
                },
                sort_keys=True,
            ).encode("ascii"),
        )
        port = 18080 if kind == "nginx" else 18081
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            require(child.poll() is None)
            if _listening(child.pid, port):
                return
            time.sleep(0.02)
        raise RuntimeError("The owned mixed-fault listener did not become ready")
    except BaseException:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=2)
        path.unlink(missing_ok=True)
        raise


def start():
    helper = filesystem()
    if CONFIG.exists():
        require(helper._read(CONFIG) == CONFIGURATION)
    else:
        helper._write(CONFIG, CONFIGURATION)
    for name in ("client-body", "proxy", "fastcgi", "uwsgi", "scgi"):
        directory = STATE / name
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077)
    if not ERROR_LOG.exists():
        helper._write(ERROR_LOG, b"")
    info = ERROR_LOG.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and not info.st_mode & 0o077
        and info.st_dev == Path("/fixture-root").stat().st_dev
    )
    _start("upstream")
    _start("nginx")


def state():
    result = {}
    for kind, port in (("nginx", 18080), ("upstream", 18081)):
        owned = _process(kind)
        if owned is None:
            result[kind + "_running"] = False
        else:
            descriptor, pid = owned
            try:
                result[kind + "_running"] = _listening(pid, port)
            finally:
                os.close(descriptor)
    return result


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        pass

    def do_GET(self):
        body = TARGET_BODY if self.path == "/healthz" else b""
        self.send_response(200 if body else 404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def upstream():
    filesystem()
    HTTPServer(("127.0.0.1", 18081), Upstream).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("start", "stop-upstream", "start-upstream", "state", "stop")
    )
    operation = parser.parse_args().operation
    try:
        filesystem()
        if operation == "start":
            start()
        elif operation == "start-upstream":
            _start("upstream")
        elif operation == "stop-upstream":
            _stop("upstream")
        elif operation == "stop":
            _stop("nginx")
            _stop("upstream")
        print(json.dumps(state(), sort_keys=True))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RuntimeError,
        subprocess.SubprocessError,
    ):
        print("The controlled mixed-fault fixture could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["_upstream"]:
        upstream()
    else:
        raise SystemExit(main())
