"""Fixed, bounded Web observation acceptance inside a newly pinned Ubuntu KVM guest."""

import argparse
import ast
import collections
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

STAGE = Path("/root/opsark-web-burst")
APP = STAGE / "app"
PROOF = STAGE / "guest-proof.json"
VHOST = Path("/etc/nginx/conf.d/opsark-vps-lab.conf")
PROFILE = Path("/etc/opsark/web-observation.json")
READER = Path("/usr/local/libexec/opsark-web-read")
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "HOME": "/root",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
    "PAGER": "cat",
}
WEB_COMMAND = "LC_ALL=C timeout -k 1s 5s /usr/bin/python3 -I /usr/local/libexec/opsark-web-read"
ASSETS = (
    "deploy/web/install.py",
    "deploy/web/read_journal.py",
    "deploy/web/nginx-format.conf",
    "deploy/readonly/install.py",
    "deploy/readonly/guard.py",
    "deploy/readonly/ssh_entry.py",
    "deploy/readonly/http_readiness.py",
    "src/opsark/web_security_events.py",
)
NORMAL_BODY = b"OPSARK_WEB_BURST_NORMAL\n"
ERROR_BODY = b"OPSARK_WEB_BURST_ERROR\n"
SENSITIVE = (
    ("/.env", "secret_probe"),
    ("/.git/HEAD", "repo_probe"),
    ("/wp-login.php", "cms_probe"),
)
VHOST_BYTES = b"""# OpsArk disposable VPS fixture v1: opsark-lab-api
server {
    listen 127.0.0.1:18880;
    server_name opsark-lab.invalid;
    access_log off;
    location = / { default_type text/plain; return 200 "OPSARK_WEB_BURST_NORMAL\\n"; }
    location = /healthz { default_type text/plain; return 200 "OPSARK_WEB_BURST_NORMAL\\n"; }
    location = /.env { default_type text/plain; return 500 "OPSARK_WEB_BURST_ERROR\\n"; }
    location = /.git/HEAD { default_type text/plain; return 500 "OPSARK_WEB_BURST_ERROR\\n"; }
    location = /wp-login.php { default_type text/plain; return 500 "OPSARK_WEB_BURST_ERROR\\n"; }
    location / { return 404; }
}
"""


class Refused(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted_directory(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "untrusted_guest_directory",
        )


def read(path, limit=65_536):
    trusted_directory(path.parent)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and not info.st_mode & 0o022
            and 0 <= info.st_size <= limit,
            "untrusted_guest_file",
        )
        data = handle.read(limit + 1)
        require(len(data) == info.st_size, "guest_file_changed")
        return data


def write(path, data, mode=0o600):
    trusted_directory(path.parent)
    if path.exists() or path.is_symlink():
        read(path)
    temporary = path.with_name("." + path.name + ".web-burst-pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def call(argv, *, timeout=15, limit=262_144):
    result = subprocess.run(  # noqa: S603 -- fixed guest-only administrator tools, no shell.
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=timeout,
        check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= limit, "fixed_guest_command_failed")
    return result.stdout


def load_state():
    if not PROOF.exists():
        return {"schema_version": 1, "traffic": {}}
    state = json.loads(read(PROOF))
    require(
        isinstance(state, dict)
        and state.get("schema_version") == 1
        and isinstance(state.get("traffic"), dict),
        "invalid_private_guest_proof",
    )
    return state


def save_state(state):
    write(PROOF, (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))


def context(expected_vm_uuid):
    require(sys.platform == "linux" and os.geteuid() == 0, "guest_root_required")
    require(
        isinstance(expected_vm_uuid, str) and str(uuid.UUID(expected_vm_uuid)) == expected_vm_uuid,
        "invalid_expected_guest_uuid",
    )
    trusted_directory(STAGE)
    require(not STAGE.stat().st_mode & 0o077, "private_guest_stage_required")
    identity = json.loads(read(STAGE / "guest-identity.json", 2048))
    require(
        set(identity) == {"schema_version", "owner", "vm_uuid", "cloud_datasource"}
        and identity["schema_version"] == 1
        and identity["owner"] == "opsark-web-burst-v1"
        and identity["cloud_datasource"] == "NoCloud"
        and str(uuid.UUID(identity["vm_uuid"])) == identity["vm_uuid"],
        "invalid_guest_identity",
    )
    actual = Path("/sys/class/dmi/id/product_uuid").read_text(encoding="ascii").strip().lower()
    require(actual == identity["vm_uuid"] == expected_vm_uuid, "guest_uuid_mismatch")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "native_systemd_required")
    require(call(["/usr/bin/cloud-id"]).strip() == b"nocloud", "native_nocloud_required")
    require(
        call(["/usr/bin/systemd-detect-virt", "--vm"]).strip() in (b"kvm", b"qemu"),
        "new_kvm_guest_required",
    )
    expected = json.loads(read(STAGE / "release-identity.json", 2048))
    require(
        set(expected) == {"commit", "manifest_sha256"}
        and re.fullmatch(r"[0-9a-f]{40}", expected["commit"])
        and re.fullmatch(r"[0-9a-f]{64}", expected["manifest_sha256"]),
        "invalid_release_identity",
    )
    manifest_raw = read(APP / "release-manifest.json", 524_288)
    require(sha(manifest_raw) == expected["manifest_sha256"], "release_manifest_mismatch")
    manifest = json.loads(manifest_raw)
    require(
        manifest["schema_version"] == 1 and manifest["commit"] == expected["commit"],
        "candidate_commit_mismatch",
    )
    indexed = {row["path"]: row for row in manifest["files"]}
    fingerprints = {}
    for name in ASSETS:
        raw = read(APP / name, 262_144)
        require(
            name in indexed
            and indexed[name]["size"] == len(raw)
            and indexed[name]["sha256"] == sha(raw)
            and b"\r" not in raw
            and raw.endswith(b"\n"),
            "canonical_deployment_source_mismatch",
        )
        fingerprints[name] = sha(raw)
    return fingerprints


def unit_properties():
    raw = call(
        [
            "/usr/bin/systemctl",
            "show",
            "nginx.service",
            "--no-pager",
            "--property=ActiveState,MainPID,ControlGroup,FragmentPath,DropInPaths",
        ]
    )
    values = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines())
    require(
        values["ActiveState"] == "active"
        and values["MainPID"].isdigit()
        and int(values["MainPID"]) > 1
        and values["ControlGroup"] == "/system.slice/nginx.service"
        and values["DropInPaths"] == "",
        "native_nginx_unit_unavailable",
    )
    fragment = Path(values["FragmentPath"]).resolve(strict=True)
    require(
        fragment == Path("/usr/lib/systemd/system/nginx.service").resolve(strict=True),
        "unexpected_nginx_unit_fragment",
    )
    read(fragment)
    process = Path("/proc") / values["MainPID"]
    require(
        (process / "exe").resolve(strict=True) == Path("/usr/sbin/nginx")
        and any(
            line.rsplit(":", 1)[-1] == values["ControlGroup"]
            for line in (process / "cgroup").read_text().splitlines()
        ),
        "native_nginx_process_unavailable",
    )
    call(["/usr/bin/systemctl", "is-active", "--quiet", "systemd-journald.service"])
    require(stat.S_ISSOCK(Path("/dev/log").stat().st_mode), "native_journal_socket_unavailable")
    endpoint = socket.inet_aton("127.0.0.1")[::-1].hex().upper() + f":{18880:04X}"
    listeners = []
    for file in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for line in file.read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A":
                listeners.append(fields[1])
    require(listeners.count(endpoint) == 1, "fixed_loopback_listener_unavailable")
    for endpoint_value in listeners:
        require(
            endpoint_value.rsplit(":", 1)[-1] not in ("0050", "01BB"),
            "unexpected_default_http_listener",
        )
    return {
        "nginx_unit_active": True,
        "journald_unit_active": True,
        "native_nginx_executable_verified": True,
        "loopback_vhost_ready": True,
    }


def configure(fingerprints):
    state = load_state()
    if VHOST.exists() or VHOST.is_symlink():
        if "profile_digest" not in state:
            require(read(VHOST) == VHOST_BYTES, "refuse_unowned_guest_vhost")
    else:
        write(VHOST, VHOST_BYTES, 0o644)
    folder = Path("/etc/opsark")
    folder.mkdir(mode=0o755, exist_ok=True)
    trusted_directory(folder)
    call(["/usr/sbin/nginx", "-t"])
    call(["/usr/bin/systemctl", "start", "nginx.service"])
    result = json.loads(
        call(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(APP / "deploy/web/install.py"),
                "install",
                "--expected-vhost-sha256",
                sha(read(VHOST)),
            ]
        )
    )
    require(
        result.get("ok") is True
        and result.get("installed") is True
        and result.get("only_lab_vhost_changed") is True,
        "official_web_install_unconfirmed",
    )
    require(
        sha(read(READER)) == fingerprints["deploy/web/read_journal.py"],
        "installed_reader_source_mismatch",
    )
    state.update(
        profile_digest=result["profile_digest"],
        source_sha256=fingerprints,
        vhost_sha256=result["vhost_sha256"],
    )
    save_state(state)
    return {
        "configured": True,
        "profile_digest": state["profile_digest"],
        "vhost_sha256": state["vhost_sha256"],
        **unit_properties(),
    }


def install(fingerprints):
    state = load_state()
    require(
        state.get("source_sha256") == fingerprints and "profile_digest" in state,
        "configure_native_producer_first",
    )
    policy = read(STAGE / "readonly-policy.json", 65_536)
    value = json.loads(policy)
    require(
        isinstance(value, dict)
        and value.get("schema_version") == 1
        and WEB_COMMAND in value.get("commands", {})
        and all(
            "opsark-patch" not in command and "opsark-defense" not in command
            for command in value["commands"]
        ),
        "readonly_web_policy_not_registered",
    )
    public = read(STAGE / "collector.pub", 8192)
    require(
        public.startswith(b"ssh-ed25519 ") and b"PRIVATE" not in public,
        "dedicated_public_key_required",
    )
    call(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(APP / "deploy/readonly/install.py"),
            "--policy",
            str(STAGE / "readonly-policy.json"),
            "--public-key",
            str(STAGE / "collector.pub"),
        ]
    )
    require(
        sha(read(Path("/etc/opsark/readonly-policy.json"))) == sha(policy),
        "installed_readonly_policy_mismatch",
    )
    state.update(
        readonly_policy_sha256=sha(policy),
        collector_public_sha256=sha(public),
        readonly_installed=True,
    )
    save_state(state)
    return {
        "readonly_installed": True,
        "profile_digest": state["profile_digest"],
        "readonly_policy_sha256": sha(policy),
    }


def readiness(fingerprints):
    state = load_state()
    require(
        state.get("source_sha256") == fingerprints and state.get("readonly_installed") is True,
        "official_guest_install_required",
    )
    result = json.loads(
        call(["/usr/bin/python3", "-I", "-B", str(APP / "deploy/web/install.py"), "status"])
    )
    require(
        result.get("ok") is True
        and result["profile_digest"] == state["profile_digest"]
        and sha(read(PROFILE)) == state["profile_digest"]
        and sha(read(READER)) == fingerprints["deploy/web/read_journal.py"]
        and sha(read(Path("/etc/opsark/readonly-policy.json"))) == state["readonly_policy_sha256"],
        "installed_guest_source_or_profile_changed",
    )
    marker = json.loads(read(Path("/etc/opsark/readonly-installed.json")))
    require(
        marker.get("installation_state") == "complete"
        and marker.get("account") == "opsark-readonly",
        "readonly_account_install_incomplete",
    )
    return {
        "ready": True,
        "profile_digest": state["profile_digest"],
        "producer_source_verified": True,
        "readonly_installed": True,
        **unit_properties(),
    }


def declared_integer(source, name):
    values = [
        node.value
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    require(
        len(values) == 1
        and isinstance(values[0], ast.Constant)
        and type(values[0].value) is int
        and values[0].value > 0,
        "fixed_producer_constant_required",
    )
    return values[0].value


def producer_stdout():
    deadline = time.monotonic() + 6
    with subprocess.Popen(  # noqa: S603 -- exact registered native readonly Web command.
        ["/usr/bin/timeout", "-k", "1s", "5s", "/usr/bin/python3", "-I", str(READER)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=ENV,
        start_new_session=True,
    ) as process:
        output = {"stdout": bytearray(), "stderr": bytearray()}
        try:
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                    if stream is None:
                        raise Refused("native_producer_pipe_unavailable")
                    selector.register(stream, selectors.EVENT_READ, label)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "native_producer_time_budget")
                    for event, _ in selector.select(min(remaining, 0.1)):
                        label = event.data
                        limit = 12288 if label == "stdout" else 1024
                        data = os.read(event.fd, min(4096, limit + 1 - len(output[label])))
                        if not data:
                            selector.unregister(event.fileobj)
                            continue
                        output[label].extend(data)
                        require(len(output[label]) <= limit, "native_producer_output_budget")
            code = process.wait(timeout=max(0.05, deadline - time.monotonic()))
            require(code == 0 and not output["stderr"], "native_producer_execution_incomplete")
            return bytes(output["stdout"])
        finally:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)


def producer_proof(fingerprints):
    readiness(fingerprints)
    before = read(PROOF)
    state = json.loads(before)
    burst = state["traffic"].get("burst", {})
    require(
        burst.get("completed") is True
        and burst.get("requests_attempted") == 240
        and burst.get("http_200") == 216
        and burst.get("http_500") == 24,
        "completed_native_burst_required",
    )
    reader_source = read(READER)
    host_source = read(APP / "src/opsark/web_security_events.py")
    window_us = declared_integer(reader_source, "WINDOW_US")
    require(
        window_us == declared_integer(host_source, "WINDOW_SECONDS") * 1_000_000
        and declared_integer(reader_source, "MAX_OUTPUT_BYTES") == 12288
        and declared_integer(reader_source, "MAX_RECORDS") == 200
        and declared_integer(reader_source, "MAX_EVENTS") == 80,
        "native_and_controller_reader_contract_differ",
    )
    raw = producer_stdout()
    require(
        0 < len(raw) <= 12288 and raw.endswith(b"\n") and raw.count(b"\n") == 1,
        "complete_native_producer_frame_required",
    )

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate_native_producer_field")
            value[key] = item
        return value

    def finite(_value):
        raise Refused("nonfinite_native_producer_field")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=unique, parse_constant=finite)
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "profile_digest",
            "window_started_us",
            "window_ended_us",
            "status",
            "gaps",
            "raw_records_seen",
            "events",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["profile_digest"] == state["profile_digest"],
        "native_producer_schema_or_profile_mismatch",
    )
    require(
        all(
            isinstance(value[key], str) and re.fullmatch(r"[0-9]{1,20}", value[key])
            for key in ("window_started_us", "window_ended_us")
        )
        and int(value["window_ended_us"]) - int(value["window_started_us"]) == window_us,
        "native_producer_window_mismatch",
    )
    limits = {"journal_record_limit", "projection_event_limit", "projection_output_limit"}
    require(
        value["status"] == "degraded"
        and isinstance(value["gaps"], list)
        and value["gaps"]
        and len(value["gaps"]) <= 20
        and all(isinstance(gap, str) and gap in limits for gap in value["gaps"])
        and len(value["gaps"]) == len(set(value["gaps"]))
        and type(value["raw_records_seen"]) is int
        and value["raw_records_seen"] == 200
        and isinstance(value["events"], list)
        and 1 <= len(value["events"]) <= 80
        and all(isinstance(event, dict) for event in value["events"]),
        "native_bounded_burst_projection_unconfirmed",
    )
    require(read(PROOF) == before, "readonly_producer_proof_changed_guest_counters")
    return {
        "profile_digest": value["profile_digest"],
        "stdout_bytes": len(raw),
        "stdout_sha256": sha(raw),
        "raw_records_seen": value["raw_records_seen"],
        "event_count": len(value["events"]),
        "status": value["status"],
        "gaps": value["gaps"],
    }


def journal_counts(started_us, count, classes, statuses):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        since = "@" + str(started_us // 1_000_000) + "." + f"{started_us % 1_000_000:06d}"
        raw = call(
            [
                "/usr/bin/journalctl",
                "--system",
                "--no-pager",
                "--output=json",
                "--lines=300",
                "--since=" + since,
                "--unit=nginx.service",
                "--identifier=opsark_web",
                "--output-fields=__CURSOR,_SYSTEMD_UNIT,_EXE,_COMM,SYSLOG_IDENTIFIER,MESSAGE",
            ],
            timeout=5,
        )
        rows = [json.loads(line) for line in raw.splitlines()]
        if len(rows) < count:
            time.sleep(0.1)
            continue
        require(len(rows) == count, "unexpected_native_request_count")
        paths, observed = collections.Counter(), collections.Counter()
        cursors = set()
        for row in rows:
            require(
                (
                    row.get("_SYSTEMD_UNIT"),
                    row.get("_EXE"),
                    row.get("_COMM"),
                    row.get("SYSLOG_IDENTIFIER"),
                )
                == ("nginx.service", "/usr/sbin/nginx", "nginx", "opsark_web"),
                "native_web_journal_metadata_mismatch",
            )
            message = json.loads(row["MESSAGE"])
            require(
                message.get("site_id") == "lab"
                and message.get("peer_ip") == "127.0.0.1"
                and message.get("method") == "GET"
                and "uri" not in message
                and "body" not in message,
                "native_web_projection_not_reduced",
            )
            paths[message["path_class"]] += 1
            observed[message["status"]] += 1
            cursors.add(row["__CURSOR"])
        require(
            len(cursors) == count and dict(paths) == classes and dict(observed) == statuses,
            "native_web_categories_or_status_counts_mismatch",
        )
        return True
    raise Refused("native_journal_delivery_not_complete")


def traffic(phase, fingerprints):
    readiness(fingerprints)
    state = load_state()
    if phase in state["traffic"]:
        previous = state["traffic"][phase]
        require(previous.get("completed") is True, "partial_traffic_cannot_be_replayed")
        return previous
    require(
        phase == "normal" or state["traffic"].get("normal", {}).get("completed") is True,
        "normal_control_required_before_burst",
    )
    total = 20 if phase == "normal" else 240
    state["traffic"][phase] = {"completed": False, "requests_attempted": 0}
    save_state(state)
    started_us = time.time_ns() // 1000
    started = time.monotonic()
    deadline = started + 35
    lock = threading.Lock()
    next_start = started
    starts, statuses = [], collections.Counter()

    def request(index):
        nonlocal next_start
        with lock:
            delay = max(0, next_start - time.monotonic())
            require(time.monotonic() + delay < deadline, "fixed_traffic_budget_exceeded")
            time.sleep(delay)
            actual = time.monotonic()
            starts.append(actual)
            next_start = actual + 0.055
        path = "/" if phase == "normal" or index < 216 else SENSITIVE[(index - 216) % 3][0]
        expected = 200 if path == "/" else 500
        connection = http.client.HTTPConnection("127.0.0.1", 18880, timeout=1)
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": "opsark-lab.invalid",
                    "Connection": "close",
                    "User-Agent": "Mozilla/5.0" if expected == 200 else "OpsArk-Controlled-Probe/1",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            body = response.read(513)
            require(
                response.status == expected
                and body == (NORMAL_BODY if expected == 200 else ERROR_BODY),
                "native_http_response_mismatch",
            )
            return response.status
        finally:
            connection.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending = set()
            for index in range(total):
                if phase == "burst" and index == 216:
                    done, pending = concurrent.futures.wait(
                        pending, timeout=max(0, deadline - time.monotonic())
                    )
                    require(not pending, "fixed_traffic_budget_exceeded")
                    statuses.update(future.result() for future in done)
                while len(pending) >= 2:
                    done, pending = concurrent.futures.wait(
                        pending,
                        timeout=max(0, deadline - time.monotonic()),
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    require(done, "fixed_traffic_budget_exceeded")
                    statuses.update(future.result() for future in done)
                require(time.monotonic() < deadline, "fixed_traffic_budget_exceeded")
                pending.add(pool.submit(request, index))
            statuses.update(
                future.result(timeout=max(0.1, deadline - time.monotonic())) for future in pending
            )
        require(
            len(starts) == total and time.monotonic() <= deadline, "fixed_traffic_budget_exceeded"
        )
        window = collections.deque()
        max_rate = 0
        for stamp in starts:
            while window and stamp - window[0] >= 1:
                window.popleft()
            window.append(stamp)
            max_rate = max(max_rate, len(window))
        require(max_rate <= 20, "fixed_traffic_rate_exceeded")
        expected_statuses = {200: 20} if phase == "normal" else {200: 216, 500: 24}
        classes = (
            {"normal": 20}
            if phase == "normal"
            else {
                "normal": 216,
                "secret_probe": 8,
                "repo_probe": 8,
                "cms_probe": 8,
            }
        )
        require(dict(statuses) == expected_statuses, "controlled_http_counts_mismatch")
        native = journal_counts(started_us, total, classes, expected_statuses)
        result = {
            "completed": True,
            "requests_attempted": total,
            "http_200": statuses[200],
            "http_500": statuses[500],
            "sensitive_categories": 0 if phase == "normal" else 3,
            "each_sensitive_category": 0 if phase == "normal" else 8,
            "maximum_concurrency": 2,
            "maximum_starts_per_second": max_rate,
            "native_journal_metadata_verified": native,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        state["traffic"][phase] = result
        save_state(state)
        return result
    except Exception:
        state["traffic"][phase] = {
            "completed": False,
            "requests_attempted": len(starts),
            "http_200": statuses[200],
            "http_500": statuses[500],
        }
        save_state(state)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-vm-uuid", required=True)
    parser.add_argument(
        "phase",
        choices=(
            "configure",
            "install",
            "readiness",
            "normal",
            "burst",
            "producer-proof",
            "restore",
            "status",
        ),
    )
    args = parser.parse_args()
    try:
        fingerprints = context(args.expected_vm_uuid)
        if args.phase == "configure":
            result = configure(fingerprints)
        elif args.phase == "install":
            result = install(fingerprints)
        elif args.phase in ("normal", "burst"):
            result = traffic(args.phase, fingerprints)
        elif args.phase == "producer-proof":
            result = producer_proof(fingerprints)
        else:
            result = readiness(fingerprints)
        print(
            json.dumps(
                result if args.phase == "producer-proof" else {"phase": args.phase, **result},
                sort_keys=True,
            )
        )
    except Refused as error:
        code = str(error)
        if re.fullmatch(r"[a-z_]{1,80}", code) is None:
            code = "controlled_guest_phase_refused"
        print(json.dumps({"phase": args.phase, "completed": False, "error": code}))
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.SubprocessError,
    ):
        print(
            json.dumps(
                {"phase": args.phase, "completed": False, "error": "controlled_guest_phase_refused"}
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
