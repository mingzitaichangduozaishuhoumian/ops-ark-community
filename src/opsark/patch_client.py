"""One bounded request to a dedicated repair entry; transport loss is never retried."""

import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import paramiko
from paramiko.hostkeys import HostKeyEntry

from opsark.config import HostConfig

COMMAND = "opsark-patch-v1"
USERNAME = "opsark-repair"
MAX_REQUEST_BYTES = 16_384
MAX_OUTPUT_BYTES = 1_048_576
MAX_ERROR_BYTES = 4096
MAX_KNOWN_HOSTS_BYTES = 1_048_576
OPERATIONS = {
    "scan",
    "prepare",
    "submit",
    "status",
    "jobs",
    "set_mode",
    "automatic_status",
    "recovery_prepare",
    "recovery_submit",
    "recovery_status",
    "activation_prepare",
    "activation_submit",
    "activation_status",
    "activation_recovery_prepare",
    "activation_recovery_submit",
    "activation_recovery_status",
}
MUTATIONS = {
    "prepare",
    "submit",
    "set_mode",
    "recovery_submit",
    "activation_submit",
    "activation_recovery_submit",
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")


class PatchClientError(RuntimeError):
    """No trustworthy remote result was obtained."""


class UnknownPatchResult(PatchClientError):
    """A mutation may have succeeded; query its original identifier before acting."""

    def __init__(self, op: str, job_id: str | None = None):
        self.op = op
        self.job_id = job_id
        super().__init__(
            "激活后的恢复结果尚未确认；请查询原恢复 ID，不要重新批准。"
            if op.startswith("activation_recovery_")
            else "服务激活结果尚未确认；请查询原激活 ID，不要重新提交。"
            if op.startswith("activation_")
            else "修改请求结果尚未确认；请查询原任务，不要重新提交新的安装任务。"
        )


@dataclass(frozen=True)
class PatchTarget:
    host: HostConfig
    key_file: Path
    policy_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.policy_digest, str) or not _DIGEST.fullmatch(self.policy_digest):
            raise ValueError("修复目标需要有效的部署策略摘要。")
        if not isinstance(self.key_file, Path):
            raise ValueError("修复密钥必须由部署端文件引用。")
        if self.key_file.resolve() == self.host.key_file.resolve():
            raise ValueError("修复通道必须使用独立于只读采集的密钥。")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Non-finite JSON number")


def _request_bytes(target: PatchTarget, request: dict) -> bytes:
    if (
        not isinstance(request, dict)
        or type(request.get("schema_version")) is not int
        or request["schema_version"] != 1
        or not isinstance(request.get("op"), str)
        or request["op"] not in OPERATIONS
        or request.get("policy_digest") != target.policy_digest
    ):
        raise ValueError("修复请求不符合固定协议或部署策略。")
    if request["op"] == "submit" and (
        set(request)
        != {
            "schema_version",
            "op",
            "policy_digest",
            "job_id",
            "plan_id",
            "plan_digest",
            "mode_revision",
        }
        or any(
            not isinstance(request.get(key), str) or not _ID.fullmatch(request[key])
            for key in ("job_id", "plan_id")
        )
        or not isinstance(request.get("plan_digest"), str)
        or not _DIGEST.fullmatch(request["plan_digest"])
        or type(request.get("mode_revision")) is not int
        or not 0 <= request["mode_revision"] <= 2**63 - 1
    ):
        raise ValueError("提交必须绑定原任务、远端计划、摘要和模式版本。")
    if request["op"].startswith(("recovery_", "activation_")):
        fields = {
            "recovery_prepare": {"job_id", "mode_revision", "context_digest"},
            "recovery_submit": {
                "recovery_id",
                "recovery_digest",
                "mode_revision",
                "context_digest",
            },
            "recovery_status": {"recovery_id"},
            "activation_prepare": {"job_id", "mode_revision", "context_digest"},
            "activation_submit": {
                "activation_id",
                "activation_digest",
                "mode_revision",
                "context_digest",
            },
            "activation_status": {"activation_id"},
            "activation_recovery_prepare": {
                "job_id",
                "activation_id",
                "mode_revision",
                "context_digest",
            },
            "activation_recovery_submit": {
                "recovery_id",
                "recovery_digest",
                "mode_revision",
                "context_digest",
            },
            "activation_recovery_status": {"recovery_id"},
        }[request["op"]]
        if set(request) != {"schema_version", "op", "policy_digest"} | fields:
            raise ValueError("恢复请求字段必须与固定操作一致。")
        for key in fields:
            value = request[key]
            if key == "mode_revision":
                valid = type(value) is int and 0 <= value <= 2**53 - 1
            else:
                expression = _ID if key.endswith("_id") else _DIGEST
                valid = isinstance(value, str) and expression.fullmatch(value) is not None
            if not valid:
                raise ValueError("恢复请求身份、摘要或模式修订无效。")
    try:
        body = json.dumps(
            request, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode()
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("修复请求不是有界 JSON。") from error
    if len(body) + 1 > MAX_REQUEST_BYTES:
        raise ValueError("修复请求超过大小限制。")
    return body + b"\n"


def _known_keys(target: PatchTarget) -> paramiko.HostKeys:
    host = target.host
    public = host.public
    if public.source != "ssh" or type(public.port) is not int or not 1 <= public.port <= 65535:
        raise ValueError("修复仅接受明确登记的 SSH 目标。")
    ipaddress.ip_address(public.address)
    expected = public.trusted_hosts_digest
    if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
        raise ValueError("修复连接需要已核验的可信主机摘要。")
    if (
        host.known_hosts_file.is_symlink()
        or target.key_file.is_symlink()
        or not target.key_file.is_file()
    ):
        raise ValueError("修复通道需要已登记的普通凭据文件。")
    with host.known_hosts_file.open("rb") as handle:
        raw = handle.read(MAX_KNOWN_HOSTS_BYTES + 1)
    if len(raw) > MAX_KNOWN_HOSTS_BYTES or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("可信主机记录已变化，需要重新核验目标身份。")
    # Parse exactly the bytes whose digest was checked, avoiding a second file read.
    keys = paramiko.HostKeys()
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entry = HostKeyEntry.from_line(line)
        if entry is None or entry.key is None:
            raise ValueError("可信主机记录包含不支持的条目。")
        for hostname in entry.hostnames:
            keys.add(hostname, entry.key.get_name(), entry.key)
    name = public.address if public.port == 22 else f"[{public.address}]:{public.port}"
    if not keys.lookup(name):
        raise ValueError("可信主机记录未包含该目标。")
    return keys


def invoke(target: PatchTarget, request: dict, timeout: float = 75) -> dict:
    """Send once; closing SSH at the deadline does not kill the detached worker."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 180:
        raise ValueError("修复请求的超时预算必须介于零至 180 秒。")
    body = _request_bytes(target, request)
    keys = _known_keys(target)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    for name in keys:
        for kind, key in keys[name].items():
            client.get_host_keys().add(name, kind, key)
    deadline = time.monotonic() + timeout
    expired = threading.Event()

    def close_at_deadline():
        expired.set()
        with suppress(OSError, paramiko.SSHException):
            client.close()

    # Paramiko's exec-request ACK wait itself has no timeout. Closing the transport
    # from this daemon watchdog also bounds that wait, without touching remote jobs.
    watchdog = threading.Timer(timeout, close_at_deadline)
    watchdog.daemon = True
    watchdog.start()
    channel = None

    def remaining():
        value = deadline - time.monotonic()
        if expired.is_set() or value <= 0:
            raise TimeoutError("Repair transport deadline")
        return value

    try:
        budget = min(4.0, remaining() / 4)
        client.connect(
            target.host.public.address,
            port=target.host.public.port,
            username=USERNAME,
            key_filename=str(target.key_file),
            look_for_keys=False,
            allow_agent=False,
            timeout=budget,
            banner_timeout=budget,
            auth_timeout=budget,
            channel_timeout=budget,
        )
        remaining()
        _stdin, stdout, _stderr = client.exec_command(COMMAND, timeout=remaining(), get_pty=False)
        channel = stdout.channel
        channel.settimeout(remaining())
        channel.sendall(body)
        channel.shutdown_write()
        output = bytearray()
        errors = bytearray()
        while True:
            remaining()
            if channel.recv_ready():
                chunk = channel.recv(min(65536, MAX_OUTPUT_BYTES - len(output) + 1))
                if len(output) + len(chunk) > MAX_OUTPUT_BYTES:
                    raise ValueError("Repair output exceeded budget")
                output.extend(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(min(4096, MAX_ERROR_BYTES - len(errors) + 1))
                if len(errors) + len(chunk) > MAX_ERROR_BYTES:
                    raise ValueError("Repair error output exceeded budget")
                errors.extend(chunk)
            if channel.closed and not channel.eof_received:
                transport = channel.get_transport()
                if transport is None or not transport.is_active():
                    raise EOFError("Repair transport closed before output EOF")
            if (
                (channel.eof_received or channel.closed)
                and channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                # A process exit status can arrive before its final channel data.
                # EOF/normal close proves no more output can arrive; drain both streams
                # first, and only read a status which cannot block past the budget.
                code = channel.recv_exit_status()
                break
            time.sleep(min(0.01, remaining()))
        remaining()
        if code != 0:
            raise ValueError("Repair entry returned no successful result")
        response = json.loads(
            output.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
        if not isinstance(response, dict):
            raise ValueError("Repair response must be an object")
        if "policy_digest" in response and response["policy_digest"] != target.policy_digest:
            raise ValueError("Repair response policy mismatch")
        if "host_id" in response and response["host_id"] != target.host.public.id:
            raise ValueError("Repair response target mismatch")
        return response
    except (paramiko.AuthenticationException, paramiko.BadHostKeyException) as error:
        raise PatchClientError("修复通道身份核验失败，未取得执行结果。") from error
    except (OSError, EOFError, ValueError, RecursionError, paramiko.SSHException) as error:
        if request["op"] in MUTATIONS:
            job_id = request.get("recovery_id", request.get("activation_id", request.get("job_id")))
            raise UnknownPatchResult(
                request["op"], job_id if isinstance(job_id, str) else None
            ) from error
        raise PatchClientError("修复通道连接、期限或响应校验失败，未取得可信结果。") from error
    finally:
        watchdog.cancel()
        if channel is not None:
            with suppress(OSError, paramiko.SSHException):
                channel.close()
        with suppress(OSError, paramiko.SSHException):
            client.close()
