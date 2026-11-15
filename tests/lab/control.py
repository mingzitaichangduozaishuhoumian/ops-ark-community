"""Fixed fault controls for the disposable lab target; run by its container owner."""

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

SCRIPT = Path("/opt/opsark-lab/upstream.py")
PID_FILE = Path("/run/opsark-lab-upstream.pid")
CONFIG = Path("/etc/nginx/conf.d/shop.conf")


def listening() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 8081), timeout=0.2):
            return True
    except OSError:
        return False


def owned_pid() -> int | None:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8"))
        arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except (OSError, ValueError):
        return None
    return pid if str(SCRIPT).encode() in arguments else None


def start() -> None:
    if owned_pid() is not None and listening():
        return
    process = subprocess.Popen(  # noqa: S603 -- fixed script inside the isolated target.
        [sys.executable, str(SCRIPT)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")
    for _ in range(50):
        if listening():
            return
        if process.poll() is not None:
            raise RuntimeError("The isolated upstream failed to start")
        time.sleep(0.1)
    with contextlib.suppress(ProcessLookupError):
        process.terminate()
    raise RuntimeError("The isolated upstream did not become ready")


def stop() -> None:
    pid = owned_pid()
    if pid is None:
        raise RuntimeError("Refusing to stop a process not owned by this fixture")
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if not listening():
            return
        time.sleep(0.1)
    raise RuntimeError("The isolated upstream did not stop")


def drift() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    before = "proxy_pass http://127.0.0.1:8081;"
    after = "proxy_pass http://127.0.0.1:8082;"
    if before not in text:
        raise RuntimeError("The lab configuration is not in its expected initial state")
    CONFIG.write_text(text.replace(before, after, 1), encoding="utf-8")
    # Deliberately do not reload Nginx: disk configuration and loaded state differ.


def probe() -> None:
    request = Request(  # noqa: S310 -- fixed loopback URL in the isolated target.
        "http://127.0.0.1:8080/healthz", headers={"Host": "shop.example.com"}
    )
    try:
        with urlopen(request, timeout=4) as response:  # noqa: S310
            code = response.status
    except HTTPError as error:
        code = error.code
    print(json.dumps({"status": code, "fixture_only": True}))


if __name__ == "__main__":
    choices = {"start": start, "stop": stop, "drift": drift, "probe": probe}
    if len(sys.argv) != 2 or sys.argv[1] not in choices:
        raise SystemExit("Choose one fixed lab control: start, stop, drift or probe")
    choices[sys.argv[1]]()
