"""An allowlisted, bounded SSH collector with strict host key checking."""

import hashlib
import shlex
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime

import paramiko
from paramiko.hostkeys import InvalidHostKey

from opsark.config import HostConfig
from opsark.health import commands_for_health, config_hash_command
from opsark.models import CheckResult, CheckStatus, Collection, Scenario
from opsark.nginx_error_window import CHECK as LOG_WINDOW_CHECK
from opsark.nginx_error_window import MAX_RECEIPT, decode_receipt, log_window_command
from opsark.platforms import assess, os_identity, required_tools, tools_command

MAX_OUTPUT_BYTES = 16_384
COMMAND_TIMEOUT = 7.0
COLLECTION_TIMEOUT = 25.0
CONNECTION_TIMEOUT = 4.0
RECEIPT_COLLECTION_TIMEOUT = 32.0
RECEIPT_COLLECTION_MARGIN = 2.0
READ_TIMEOUT_CLOSE_GRACE = 0.1
_READ_TIMEOUT_MARKER = "_opsark_read_check_timed_out"

_OS_RELEASE = "timeout -k 1s 5s cat /etc/os-release"
_NGINX_STATUS = "timeout -k 1s 5s systemctl is-active nginx"
_DISK_BYTES = "timeout -k 1s 5s df -Pk /"
_DISK_INODES = "timeout -k 1s 5s df -Pi /"
_DOCKER = (
    "env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY "
    "-u DOCKER_CERT_PATH docker --host unix:///var/run/docker.sock"
)
_COMPOSE_VERSION = f"timeout -k 1s 5s {_DOCKER} compose version --short"
_DOCKER_ROOTFUL = f"timeout -k 1s 5s {_DOCKER} info --format " + shlex.quote(
    '{"OSType":{{json .OSType}},"SecurityOptions":{{json .SecurityOptions}}}'
)


def _inspect_command(container: str) -> str:
    inspect_format = (
        '{"Name":{{json .Name}},"State":{'
        '"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
        '"OOMKilled":{{json .State.OOMKilled}},"ExitCode":{{json .State.ExitCode}}},'
        '"Image":{{json .Image}},"ImageReference":{{json .Config.Image}},'
        '"RestartCount":{{.RestartCount}},"MemoryLimit":{{.HostConfig.Memory}},'
        '"Ports":{{json .NetworkSettings.Ports}}}'
    )
    return (
        f"timeout -k 1s 5s {_DOCKER} inspect --format {shlex.quote(inspect_format)} "
        + shlex.quote(container)
    )


def commands_for(host: HostConfig, scenario: Scenario) -> dict[str, str]:
    container = shlex.quote(host.public.container_name)
    inspect = _inspect_command(host.public.container_name)
    available = {
        "web_502": {
            "nginx_status": _NGINX_STATUS,
            **(
                {LOG_WINDOW_CHECK: log_window_command(host.public.site_domain)}
                if host.nginx_error_window_enabled
                else {"nginx_errors": "timeout -k 1s 5s tail -n 80 -- /var/log/nginx/error.log"}
            ),
            "listeners": "timeout -k 1s 5s ss -lnt",
            "container_state": inspect,
        },
        "disk": {
            "disk_bytes": _DISK_BYTES,
            "disk_inodes": _DISK_INODES,
            "disk_directories": (
                "timeout -k 1s 5s nice -n 10 du -xsk -- "
                "/var/log/nginx /var/log/journal /srv /var/lib/docker/containers"
            ),
        },
        "container_restart": {
            "container_state": inspect,
            "container_logs": f"timeout -k 1s 5s {_DOCKER} logs --tail 80 {container}",
            "memory_events": (
                "timeout -k 1s 5s journalctl -k -n 80 --since '15 minutes ago' "
                "--no-pager -o short-iso"
            ),
        },
        "ssh_security": {
            "ssh_auth": (
                "timeout -k 1s 5s journalctl -u ssh -n 100 --since '15 minutes ago' "
                "--no-pager -o short-iso"
            ),
        },
    }
    if scenario not in available:
        raise ValueError("不支持的检查场景。")
    commands = {
        "os_release": _OS_RELEASE,
        "platform_tools": tools_command(),
        **available[scenario],
    }
    if scenario == "disk" and host.public.disk_reclaim_scope_digest is not None:
        commands.pop("disk_directories")
        commands["disk_reclaim"] = disk_reclaim_command(host)
    if not host.container_binding_confirmed:
        commands.pop("container_state", None)
        commands.pop("container_logs", None)
    if host.public.nginx_config_path:
        commands["nginx_config_hash"] = config_hash_command(host.public.nginx_config_path)
    return {**commands, **commands_for_health(host.public)}


def run_check(
    client: paramiko.SSHClient,
    name: str,
    command: str,
    budget: float,
    *,
    output_limit: int = MAX_OUTPUT_BYTES,
    require_eof: bool = False,
) -> CheckResult:
    """Bound channel open, exec acknowledgement and both output streams."""
    started = time.monotonic()
    deadline = started + budget
    if budget <= 0:
        return CheckResult(name=name, status="timeout", exit_code=None)
    try:
        get_transport = getattr(client, "get_transport", None)
        transport = get_transport() if get_transport is not None else None
        target = transport if get_transport is not None else client
        if target is None:
            raise paramiko.SSHException("No registered transport")
        if getattr(target, _READ_TIMEOUT_MARKER, False) is True:
            return CheckResult(name=name, status="timeout", exit_code=None)
        if transport is not None and not transport.is_active():
            raise paramiko.SSHException("Registered transport closed")
    except (OSError, paramiko.SSHException):
        return CheckResult(
            name=name,
            status="error",
            exit_code=None,
            stderr="SSH 检查连接已关闭，未执行后续检查。",
        )
    expired = threading.Event()
    lifecycle = threading.Lock()
    finished = False

    def mark_expired():
        expired.set()
        with suppress(AttributeError, TypeError):
            setattr(target, _READ_TIMEOUT_MARKER, True)

    def close_at_deadline():
        with lifecycle:
            if finished and not expired.is_set():
                return
            mark_expired()
        # Capture this connection once. A late callback must never close a new
        # Transport installed on the same SSHClient by a later collection.
        with suppress(Exception):
            target.close()

    watchdog = threading.Timer(max(0, deadline - time.monotonic()), close_at_deadline)
    watchdog.daemon = True
    stdout_data = bytearray()
    stderr_data = bytearray()
    status: CheckStatus = "ok"
    truncated = False
    exit_code = None
    channel = None
    try:
        # Paramiko's Channel.exec_command waits for an event without applying
        # channel.settimeout. Closing this exact Transport releases that wait.
        watchdog.start()
        if transport is not None:
            # The collection's outer deadline can close the SSHClient, or its
            # owner can replace that client's Transport after the check above.
            # Both dispatch and the deadline stay bound to the captured object.
            channel = transport.open_session(timeout=budget)
            channel.settimeout(budget)
            channel.exec_command("LC_ALL=C " + command)
            channel.shutdown_write()
        else:
            # Existing test/read adapters expose only this narrow interface.
            stdin, stdout, _ = client.exec_command("LC_ALL=C " + command, timeout=budget)
            stdin.close()
            channel = stdout.channel
        while True:
            if time.monotonic() >= deadline:
                status = "timeout"
                break
            remaining = output_limit - len(stdout_data) - len(stderr_data)
            if remaining <= 0:
                truncated = True
                break
            if channel.recv_ready():
                stdout_data.extend(channel.recv(min(4096, remaining)))
            remaining = output_limit - len(stdout_data) - len(stderr_data)
            if remaining > 0 and channel.recv_stderr_ready():
                stderr_data.extend(channel.recv_stderr(min(4096, remaining)))
            # Exit status can precede the remaining bytes; empty buffers are not EOF.
            if (
                channel.exit_status_ready()
                and (channel.eof_received or channel.closed)
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                exit_code = channel.recv_exit_status()
                transport = channel.get_transport()
                if not channel.eof_received and (
                    require_eof or transport is None or not transport.is_active()
                ):
                    # A dead transport also marks channels closed; it cannot
                    # prove that the peer finished delivering either stream.
                    status = "error"
                    remaining = output_limit - len(stdout_data) - len(stderr_data)
                    stderr_data.extend(
                        "\nSSH 连接在输出结束前中断，已读内容不能作为完整结果。".encode()[
                            :remaining
                        ]
                    )
                break
            time.sleep(0.01)
        if status != "timeout" and exit_code not in (0, None):
            status = "timeout" if exit_code in (124, 137) else "error"
        if name.startswith("http_") and exit_code == 28:
            status = "timeout"
        if name.startswith("http_") and exit_code == 63:
            truncated = True
        if name.startswith("http_") and status == "ok":
            try:
                stdout_data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                status = "error"
                stderr_data.extend("\n站点响应无法按完整 UTF-8 文本核验正文条件。".encode())
        error_text = stderr_data.decode("utf-8", errors="replace").lower()
        if status == "error" and any(
            word in error_text for word in ("permission denied", "access denied", "not permitted")
        ):
            status = "permission_denied"
        if name in {"memory_events", "ssh_auth"} and any(
            hint in error_text
            for hint in (
                "not seeing messages from other users",
                "no journal files were opened due to insufficient permissions",
            )
        ):
            status = "permission_denied"
        if name == "container_logs" and status == "ok" and exit_code == 0:
            # Docker forwards the application's stderr as stderr even when the CLI succeeds.
            stdout_data.extend(b"\n" if stdout_data and stderr_data else b"")
            stdout_data.extend(stderr_data)
            stderr_data.clear()
    except TimeoutError:
        status = "timeout"
        stderr_data = bytearray("SSH 检查超时，未取得完整结果。".encode())
    except (EOFError, OSError, RuntimeError, paramiko.SSHException):
        status = "error"
        stderr_data = bytearray("SSH 检查通道中断，未取得完整结果。".encode())
    finally:
        try:
            if channel is not None:
                channel.close()
        except (EOFError, OSError, paramiko.SSHException):
            # A close frame can race a disconnected packetizer after reading
            # finished. Its known network errors must not escape the result.
            if status != "timeout":
                status = "error"
            exit_code = None
            stderr_data = bytearray("SSH 检查通道中断，未取得完整结果。".encode())
        finally:
            with lifecycle:
                if time.monotonic() >= deadline:
                    mark_expired()
                finished = True
            if not expired.is_set():
                watchdog.cancel()
            # The callback never holds lifecycle while closing. If close's
            # local tail is delayed, only the poisoned old Transport remains
            # reachable; a later check cannot reuse it or close a new one.
            if watchdog.ident is not None:
                watchdog.join(timeout=READ_TIMEOUT_CLOSE_GRACE)
    if expired.is_set():
        status, exit_code = "timeout", None
    return CheckResult(
        name=name,
        status=status,
        stdout=stdout_data.decode("utf-8", errors="replace"),
        stderr=stderr_data.decode("utf-8", errors="replace"),
        exit_code=exit_code,
        duration_ms=round((time.monotonic() - started) * 1000),
        truncated=truncated,
    )


def collect_ssh(host: HostConfig, scenario: Scenario) -> Collection:
    collection = _collect(host, commands_for(host, scenario))
    if host.nginx_error_window_enabled and scenario == "web_502":
        for index, check in enumerate(collection.checks):
            if check.name != LOG_WINDOW_CHECK:
                continue
            window, blocked = decode_receipt(check, collection.started_at, datetime.now(UTC))
            collection.nginx_error_window = window
            collection.nginx_error_window_blocked = blocked
            status: CheckStatus = (
                "permission_denied"
                if window.status == "permission_denied"
                else "ok"
                if window.status == "observed"
                else "unavailable"
            )
            collection.checks[index] = CheckResult(
                name="nginx_errors",
                status=status,
                exit_code=0 if status == "ok" else None,
                duration_ms=check.duration_ms,
            )
            break
    if (
        not host.container_binding_confirmed
        and scenario in {"web_502", "container_restart"}
        and not any(check.name == "connection" for check in collection.checks)
    ):
        missing = (
            ("container_state", "container_logs")
            if scenario == "container_restart"
            else ("container_state",)
        )
        collection.checks.extend(
            CheckResult(
                name=name,
                status="unavailable",
                exit_code=None,
                stderr="容器映射尚未确认，未采集容器状态或日志。",
            )
            for name in missing
        )
    return collection


def commands_for_preflight(host: HostConfig) -> dict[str, str]:
    """The collector and exported exact policy share the same fixed probes."""
    commands = {
        "os_release": _OS_RELEASE,
        "platform_tools": tools_command(),
        "nginx_status": _NGINX_STATUS,
        "container_state": _inspect_command(host.public.container_name),
        "disk_bytes": _DISK_BYTES,
        "disk_inodes": _DISK_INODES,
        "compose_version": _COMPOSE_VERSION,
        "docker_rootful": _DOCKER_ROOTFUL,
    }
    if not host.container_binding_confirmed:
        commands.pop("container_state")
    return commands


def nginx_dependencies_command(host: HostConfig) -> str:
    """No API/model parameter reaches the root-owned dependency projection helper."""
    if host.nginx_scope_digest is None or host.compose_project is None:
        raise ValueError("Nginx dependency scope is not registered")
    return "timeout -k 1s 5s /usr/local/libexec/opsark-nginx-dependencies"


def disk_reclaim_command(host: HostConfig) -> str:
    """The root-owned scope supplies every path/PID; callers supply no arguments."""
    if host.public.disk_reclaim_scope_digest is None:
        raise ValueError("Disk metadata scope is not registered")
    return "timeout -k 1s 5s /usr/local/libexec/opsark-disk-reclaim"


def collect_ssh_preflight(host: HostConfig) -> Collection:
    """Verify basic collection and first-release rootful Compose v2 capability."""
    return _collect(host, commands_for_preflight(host))


def _connect_registered(client: paramiko.SSHClient, host: HostConfig) -> None:
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    if host.public.trusted_hosts_digest is not None:
        with host.known_hosts_file.open("rb") as handle:
            actual_digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual_digest != host.public.trusted_hosts_digest:
            raise ValueError("可信主机记录已变化，需要重新加载登记。")
    try:
        client.load_host_keys(str(host.known_hosts_file))
    except InvalidHostKey:
        raise ValueError("可信主机记录格式不正确。") from None
    client.connect(
        hostname=host.public.address,
        port=host.public.port,
        username=host.public.username,
        key_filename=str(host.key_file),
        allow_agent=False,
        look_for_keys=False,
        timeout=CONNECTION_TIMEOUT,
        auth_timeout=CONNECTION_TIMEOUT,
        banner_timeout=CONNECTION_TIMEOUT,
        channel_timeout=COMMAND_TIMEOUT,
    )


def collect_business_receipts(host: HostConfig, commands: dict[str, str]) -> dict[str, CheckResult]:
    """Read only the small receipt protocol, separately from investigation evidence."""
    return collect_registered_receipts(host, commands, output_limit=96)


def collect_registered_receipts(
    host: HostConfig, commands: dict[str, str], *, output_limit: int
) -> dict[str, CheckResult]:
    """Read bounded complete replies over the pinned management connection."""
    return collect_registered_connection(host, commands, output_limit=output_limit)[1]


def collect_registered_connection(
    host: HostConfig, commands: dict[str, str], *, output_limit: int
) -> tuple[bool, dict[str, CheckResult]]:
    """Report the authenticated connection and receipts from that same SSH session."""
    if not commands or host.public.trusted_hosts_digest is None:
        return False, {}
    client = paramiko.SSHClient()
    expired = threading.Event()
    connected = False

    def close_at_deadline():
        expired.set()
        with suppress(Exception):
            client.close()

    # Paramiko's exec acknowledgement wait is not bounded by channel.settimeout.
    # Closing the real transport also releases that wait when the peer goes silent.
    budget = min(
        RECEIPT_COLLECTION_TIMEOUT,
        CONNECTION_TIMEOUT + len(commands) * COMMAND_TIMEOUT + RECEIPT_COLLECTION_MARGIN,
    )
    watchdog = threading.Timer(budget, close_at_deadline)
    watchdog.daemon = True
    watchdog.start()
    try:
        _connect_registered(client, host)
        connected = not expired.is_set()
        results = {}
        for name, command in commands.items():
            if expired.is_set():
                break
            result = run_check(
                client, name, command, COMMAND_TIMEOUT, output_limit=output_limit, require_eof=True
            )
            if expired.is_set():
                results[name] = CheckResult(
                    name=name,
                    status="timeout",
                    stderr="只读回执采集达到总时间预算，未取得完整结果。",
                    exit_code=None,
                )
                break
            results[name] = result
        return connected, results
    except (OSError, ValueError, paramiko.SSHException):
        return connected, {}
    finally:
        watchdog.cancel()
        client.close()


def _collect(host: HostConfig, commands: dict[str, str]) -> Collection:
    started_at = datetime.now(UTC)
    started = time.monotonic()
    client = paramiko.SSHClient()
    checks: list[CheckResult] = []
    try:
        _connect_registered(client, host)
        checks_started = time.monotonic()
        for name, command in commands.items():
            reason = None
            if name != "os_release":
                os_id, _ = os_identity(checks[0])
                if os_id not in {"ubuntu", "debian"}:
                    reason = "系统未识别或不在 Ubuntu / Debian 适配范围，该检查未执行。"
                elif name != "platform_tools":
                    assessment = assess(checks)
                    if assessment.status != "compatible":
                        reason = "架构或工具预检未通过，该检查未执行。"
                    else:
                        missing = set(required_tools(name)) - set(assessment.available_tools)
                        if missing:
                            reason = (
                                "缺少检查所需工具：" + ", ".join(sorted(missing)) + "；未执行。"
                            )
            if reason:
                checks.append(
                    CheckResult(name=name, status="unavailable", stderr=reason, exit_code=None)
                )
                continue
            remaining = COLLECTION_TIMEOUT - (time.monotonic() - checks_started)
            if remaining <= 0:
                checks.append(
                    CheckResult(
                        name=name,
                        status="timeout",
                        stderr="调查已达到总时间预算，该检查未执行。",
                        exit_code=None,
                    )
                )
            else:
                budget = min(COMMAND_TIMEOUT, remaining)
                checks.append(
                    run_check(
                        client, name, command, budget, output_limit=MAX_RECEIPT, require_eof=True
                    )
                    if name == LOG_WINDOW_CHECK
                    else run_check(client, name, command, budget)
                )
    except TimeoutError:
        checks.append(
            CheckResult(
                name="connection",
                status="timeout",
                stderr="SSH 连接超时，未取得主机状态。",
                exit_code=None,
            )
        )
    except paramiko.AuthenticationException:
        checks.append(
            CheckResult(
                name="connection",
                status="permission_denied",
                stderr="SSH 身份验证失败；请核验登记的专用账号与凭据。",
                exit_code=None,
            )
        )
    except (OSError, ValueError, paramiko.SSHException):
        checks.append(
            CheckResult(
                name="connection",
                status="error",
                stderr="SSH 连接或主机身份校验失败；请核验目标、可信主机记录与连接状态。",
                exit_code=None,
            )
        )
    finally:
        client.close()
    return Collection(
        host_id=host.public.id,
        source="ssh",
        started_at=started_at,
        checks=checks,
        duration_ms=round((time.monotonic() - started) * 1000),
    )
