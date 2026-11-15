"""Build a local SSH enrollment preview from an independently pinned public key."""

import base64
import hashlib
import hmac
import ipaddress
import json
import re
from typing import Literal

import paramiko
from paramiko.pkey import UnknownKeyType
from pydantic import ConfigDict, Field

from opsark.config import COMPOSE_PROJECT, DOMAIN, IDENTIFIER, USERNAME
from opsark.models import StrictModel

_HOST_KEY_TYPES = frozenset(
    {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_INVALID_KEY = "请输入一行有效的 OpenSSH 公开主机密钥。"


class HostOnboardingError(ValueError):
    """A preview was refused without including any submitted values in the error."""


class HostOnboardingRequest(StrictModel):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    host_id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    address: str = Field(min_length=1, max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="opsark-readonly", min_length=1, max_length=32)
    site_domain: str = Field(min_length=1, max_length=253)
    container_name: str | None = Field(default=None, min_length=1, max_length=80)
    expected_upstream_port: int = Field(default=8081, ge=1, le=65535)
    compose_project: str | None = Field(default=None, max_length=63)
    host_key: str = Field(min_length=1, max_length=8192, repr=False)
    expected_fingerprint: str = Field(min_length=1, max_length=50, repr=False)


type KnownHostsVariant = Literal["lf", "crlf", "no_final_newline"]


class HostOnboarding(StrictModel):
    host_id: str
    address: str
    port: int
    fingerprint: str
    known_hosts: str
    inventory: str
    key_file: str
    known_hosts_file: str
    known_hosts_digests: dict[KnownHostsVariant, str]


def _has_public_fields(raw: bytes, kind: str) -> bool:
    algorithm = kind.encode("ascii")
    prefix = len(algorithm).to_bytes(4, "big") + algorithm
    if not raw.startswith(prefix):
        return False
    position = len(prefix)
    for _ in range(1 if kind == "ssh-ed25519" else 2):
        start = position + 4
        if start >= len(raw):
            return False
        length = int.from_bytes(raw[position:start], "big")
        if not 0 < length <= len(raw) - start:
            return False
        position = start + length
    return position == len(raw)


def _public_key(value: str) -> tuple[str, str, bytes]:
    line = value.removesuffix("\r\n") if value.endswith("\r\n") else value.removesuffix("\n")
    if not line.replace("\t", " ").isprintable():
        raise HostOnboardingError(_INVALID_KEY)
    parts = line.split(maxsplit=2)
    if len(parts) < 2 or parts[0] not in _HOST_KEY_TYPES or not _BASE64.fullmatch(parts[1]):
        raise HostOnboardingError(_INVALID_KEY)
    kind, encoded = parts[:2]
    try:
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded or not _has_public_fields(raw, kind):
            raise ValueError
        key = paramiko.PKey.from_type_string(kind, raw)
        if key.get_name() != kind or key.asbytes() != raw:
            raise ValueError
    except (ValueError, OverflowError, paramiko.SSHException, UnknownKeyType):
        raise HostOnboardingError(_INVALID_KEY) from None
    return kind, encoded, raw


def _address(value: str) -> str:
    try:
        if "%" in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HostOnboardingError("请输入不带接口范围的 IPv4 或 IPv6 地址。") from None


def prepare_host_onboarding(body: HostOnboardingRequest) -> HostOnboarding:
    """Verify a public key and render the exact pin and an editable inventory snippet."""
    if not IDENTIFIER.fullmatch(body.host_id) or (
        body.container_name is not None and not IDENTIFIER.fullmatch(body.container_name)
    ):
        raise HostOnboardingError("主机或容器标识包含不支持的字符。")
    if not USERNAME.fullmatch(body.username) or body.username == "root":
        raise HostOnboardingError("请使用专用的非 root SSH 账号。")
    if not DOMAIN.fullmatch(body.site_domain):
        raise HostOnboardingError("网站域名格式不正确。")
    if body.compose_project is not None and COMPOSE_PROJECT.fullmatch(body.compose_project) is None:
        raise HostOnboardingError("Compose 发现范围需要一个安全的项目标识。")
    if body.container_name is None and body.compose_project is None:
        raise HostOnboardingError("请填写已确认容器，或先授权一个 Compose 项目用于只读发现。")
    name = body.name.strip()
    if not name or not body.name.isprintable():
        raise HostOnboardingError("主机名称需为单行可见文本。")
    address = _address(body.address)
    if not _FINGERPRINT.fullmatch(body.expected_fingerprint):
        raise HostOnboardingError("请输入通过可信渠道取得的 OpenSSH SHA256 指纹。")
    kind, encoded, raw = _public_key(body.host_key)
    encoded_digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    fingerprint = "SHA256:" + encoded_digest
    if not hmac.compare_digest(fingerprint, body.expected_fingerprint):
        raise HostOnboardingError("公开主机密钥与预期指纹不一致。")

    pin = address if body.port == 22 else f"[{address}]:{body.port}"
    known_line = f"{pin} {kind} {encoded}"
    credential = f"readonly-{body.host_id}"
    key_file = f"ssh/opsark-{body.host_id}-readonly"
    known_hosts_file = f"ssh/opsark-{body.host_id}-known-hosts"
    fields = {
        "id": body.host_id,
        "name": name,
        "address": address,
        "port": body.port,
        "username": body.username,
        "credential": credential,
        "site_domain": body.site_domain,
        "expected_upstream_port": body.expected_upstream_port,
    }
    if body.container_name is None:
        fields["container_binding_confirmed"] = False
    else:
        # Preserve the pre-existing, explicitly registered path and its TOML order.
        port = fields.pop("expected_upstream_port")
        fields["container_name"] = body.container_name
        fields["expected_upstream_port"] = port
    if body.compose_project is not None:
        fields["compose_project"] = body.compose_project
    inventory = "\n".join(
        [
            f"[credentials.{json.dumps(credential)}]",
            f"key_file = {json.dumps(key_file)}",
            f"known_hosts_file = {json.dumps(known_hosts_file)}",
            "",
            "[[hosts]]",
            *(
                f"{field} = {json.dumps(value, ensure_ascii=False)}"
                for field, value in fields.items()
            ),
            "",
        ]
    )
    known_bytes = known_line.encode("ascii")
    return HostOnboarding(
        host_id=body.host_id,
        address=address,
        port=body.port,
        fingerprint=fingerprint,
        known_hosts=known_line + "\n",
        inventory=inventory,
        key_file=key_file,
        known_hosts_file=known_hosts_file,
        known_hosts_digests={
            "lf": hashlib.sha256(known_bytes + b"\n").hexdigest(),
            "crlf": hashlib.sha256(known_bytes + b"\r\n").hexdigest(),
            "no_final_newline": hashlib.sha256(known_bytes).hexdigest(),
        },
    )
