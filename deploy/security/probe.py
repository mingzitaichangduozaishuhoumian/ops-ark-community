#!/usr/bin/python3 -I
"""Administrator-only, loopback SSH probe isolated from the primary SSH service."""

import argparse
import contextlib
import hashlib
import json
import os
import socket
import stat
import subprocess
from pathlib import Path

SOURCE = Path("/usr/sbin/sshd")
BINARY = Path("/usr/local/libexec/opsark-sshd-lab")
CONFIG_DIR = Path("/etc/opsark/security-probe")
CONFIG = CONFIG_DIR / "sshd_config"
UNIT = Path("/etc/systemd/system/opsark-security-probe.service")
MARKER = Path("/etc/opsark/security-probe-owned.json")
SERVICE = "opsark-security-probe.service"
OWNER = "opsark-security-probe/v1"
PORT = 23999
MAX_BINARY_BYTES = 16_777_216
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/root"}

CONFIG_TEXT = """# OpsArk isolated security probe v1
AddressFamily inet
ListenAddress 127.0.0.1
Port 23999
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/opsark-security-probe.pid
AllowUsers opsark-readonly
AuthorizedKeysFile /var/lib/opsark-readonly/.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
PermitUserRC no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTTY no
PermitTunnel no
GatewayPorts no
LogLevel VERBOSE
SyslogFacility LOCAL6
UseDNS no
MaxAuthTries 2
MaxSessions 2
MaxStartups 3:30:6
LoginGraceTime 15
StrictModes yes
PrintMotd no
PrintLastLog no
"""

UNIT_TEXT = """# OpsArk isolated security probe v1
[Unit]
Description=OpsArk controlled loopback SSH security probe
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/opsark-sshd-lab -D -e -f /etc/opsark/security-probe/sshd_config
SyslogIdentifier=opsark-security-probe
StandardOutput=journal
StandardError=journal
Restart=no
RuntimeMaxSec=900
MemoryMax=128M
TasksMax=32
CPUQuota=20%
PrivateTmp=yes
KillMode=control-group
TimeoutStopSec=10
"""


class ProbeError(ValueError):
    """Safe operator-facing error code, without raw daemon diagnostics."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require_root():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ProbeError("administrator_root_required")


def trusted_directory(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProbeError("untrusted_deployment_directory")


def read_trusted(path, limit, *, private=False):
    trusted_directory(path.parent)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_nlink != 1
        or info.st_size > limit
        or (private and stat.S_IMODE(info.st_mode) != 0o600)
    ):
        raise ProbeError("untrusted_deployment_file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            raise ProbeError("deployment_file_changed")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ProbeError("deployment_file_too_large")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("duplicate_ownership_field")
        result[key] = value
    return result


def expected_payloads():
    binary = read_trusted(SOURCE, MAX_BINARY_BYTES)
    return {str(BINARY): binary, str(CONFIG): CONFIG_TEXT.encode(), str(UNIT): UNIT_TEXT.encode()}


def marker_state():
    if not MARKER.exists() and not MARKER.is_symlink():
        return None
    try:
        marker = json.loads(
            read_trusted(MARKER, 8192, private=True), object_pairs_hook=unique_object
        )
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid_ownership_marker") from error
    if (
        not isinstance(marker, dict)
        or set(marker) != {"owner", "state", "sha256"}
        or marker["owner"] != OWNER
        or not isinstance(marker["state"], str)
        or marker["state"] not in {"installing", "complete"}
        or not isinstance(marker["sha256"], dict)
        or set(marker["sha256"]) != {str(BINARY), str(CONFIG), str(UNIT)}
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in marker["sha256"].values()
        )
    ):
        raise ProbeError("invalid_ownership_marker")
    return marker


def verify_existing(planned, marker, *, require_complete=False):
    if marker is None:
        if any(path.exists() or path.is_symlink() for path in (BINARY, CONFIG_DIR, CONFIG, UNIT)):
            raise ProbeError("refusing_unowned_probe_paths")
        if require_complete:
            raise ProbeError("probe_not_installed")
        return
    if marker["sha256"] != {name: digest(data) for name, data in planned.items()}:
        raise ProbeError("system_sshd_or_planned_configuration_changed_review_required")
    if require_complete and marker["state"] != "complete":
        raise ProbeError("probe_installation_incomplete")
    if CONFIG_DIR.exists() or CONFIG_DIR.is_symlink():
        trusted_directory(CONFIG_DIR)
    for name, content in planned.items():
        path = Path(name)
        if not path.exists() and not path.is_symlink():
            if marker["state"] == "complete":
                raise ProbeError("owned_probe_file_missing")
            continue
        if read_trusted(path, MAX_BINARY_BYTES) != content:
            raise ProbeError("owned_probe_file_changed")


def write_owned(path, data, mode):
    trusted_directory(path.parent)
    temporary = path.with_name("." + path.name + ".opsark-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def execute(argv):
    try:
        return subprocess.run(  # noqa: S603 -- only fixed administrator actions and reviewed paths.
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=ENVIRONMENT.copy(),
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProbeError("probe_command_did_not_complete") from error


def active_state():
    result = execute(["/usr/bin/systemctl", "show", "--property=ActiveState", "--value", SERVICE])
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def install():
    for directory in (BINARY.parent, UNIT.parent, MARKER.parent):
        trusted_directory(directory)
    planned = expected_payloads()
    marker = marker_state()
    verify_existing(planned, marker)
    if marker is not None and marker["state"] == "complete":
        return {"action": "install", "installed": True, "idempotent": True, "started": False}
    state = {
        "owner": OWNER,
        "state": "installing",
        "sha256": {name: digest(data) for name, data in planned.items()},
    }
    write_owned(MARKER, (json.dumps(state, sort_keys=True) + "\n").encode(), 0o600)
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(mode=0o700)
        os.chmod(CONFIG_DIR, 0o700)
        os.chown(CONFIG_DIR, 0, 0)
    trusted_directory(CONFIG_DIR)
    for name, content in planned.items():
        mode = 0o755 if name == str(BINARY) else 0o644 if name == str(UNIT) else 0o600
        write_owned(Path(name), content, mode)
    if execute([str(BINARY), "-t", "-f", str(CONFIG)]).returncode != 0:
        raise ProbeError("probe_syntax_check_failed")
    if execute(["/usr/bin/systemctl", "daemon-reload"]).returncode != 0:
        raise ProbeError("probe_daemon_reload_failed")
    state["state"] = "complete"
    write_owned(MARKER, (json.dumps(state, sort_keys=True) + "\n").encode(), 0o600)
    return {"action": "install", "installed": True, "idempotent": False, "started": False}


def verify_installation():
    planned = expected_payloads()
    verify_existing(planned, marker_state(), require_complete=True)
    return planned


def port_available():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", PORT))
        except OSError:
            return False
    return True


def start():
    verify_installation()
    if active_state() == "active":
        return {"action": "start", "active": True, "already_active": True}
    if not port_available():
        raise ProbeError("probe_loopback_port_occupied")
    if execute([str(BINARY), "-t", "-f", str(CONFIG)]).returncode != 0:
        raise ProbeError("probe_syntax_check_failed")
    if execute(["/usr/bin/systemctl", "start", SERVICE]).returncode != 0:
        raise ProbeError("probe_start_failed")
    return {"action": "start", "active_state": active_state(), "bound_address": "127.0.0.1:23999"}


def stop():
    verify_installation()
    if execute(["/usr/bin/systemctl", "stop", SERVICE]).returncode != 0:
        raise ProbeError("probe_stop_failed")
    return {"action": "stop", "active_state": active_state(), "journal_not_cleared": True}


def status():
    planned = verify_installation()
    result = execute(
        [
            "/usr/bin/journalctl",
            "--system",
            "--no-pager",
            "--output=json",
            "--lines=3",
            "--unit=" + SERVICE,
            "--output-fields=_COMM,_EXE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER",
        ]
    )
    metadata = []
    if result.returncode == 0:
        for line in result.stdout.splitlines()[:3]:
            try:
                row = json.loads(line, object_pairs_hook=unique_object)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(row, dict):
                continue
            metadata.append(
                {
                    key: row.get(key) if isinstance(row.get(key), str) else None
                    for key in (
                        "__REALTIME_TIMESTAMP",
                        "_COMM",
                        "_EXE",
                        "_SYSTEMD_UNIT",
                        "SYSLOG_IDENTIFIER",
                    )
                }
            )
    return {
        "action": "status",
        "installed": True,
        "active_state": active_state(),
        "binary_sha256": digest(planned[str(BINARY)]),
        "system_sshd_sha256": digest(read_trusted(SOURCE, MAX_BINARY_BYTES)),
        "bound_address": "127.0.0.1:23999",
        "journal_metadata": metadata,
        "journal_query_succeeded": result.returncode == 0,
        "protection_rules_checked": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "start", "stop", "status"))
    arguments = parser.parse_args()
    try:
        require_root()
        os.umask(0o077)
        result = {
            "ok": True,
            **{"install": install, "start": start, "stop": stop, "status": status}[
                arguments.action
            ](),
        }
    except (ProbeError, OSError, ValueError) as error:
        result = {
            "ok": False,
            "action": arguments.action,
            "error": str(error) if isinstance(error, ProbeError) else "probe_operation_failed",
        }
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
