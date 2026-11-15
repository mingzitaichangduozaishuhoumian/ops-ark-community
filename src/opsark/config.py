"""Deployment-owned settings and an explicit SSH target inventory."""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import ValidationError

from opsark.health import commands_for_health, config_hash_command
from opsark.models import BusinessCheck, HealthCheck, HostPublic
from opsark.nginx_error_window import valid_site

if TYPE_CHECKING:
    from opsark.patch_client import PatchTarget

PROJECT_ROOT = Path(__file__).resolve().parents[2]
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}\Z")
DOMAIN = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\Z")
USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
COMPOSE_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    token: str
    inventory_path: Path | None = None
    ai_base_url: str | None = None
    ai_key: str | None = None
    ai_model: str | None = None
    ai_key_file: Path | None = None
    ai_response_format: str = "json_object"
    ai_token_limit_parameter: str = "max_tokens"  # noqa: S105 -- API field name, not a credential.
    ai_max_output_tokens: int = 2048
    ai_thinking_mode: str = "provider_default"
    observation_enabled: bool = False
    observation_host_ids: tuple[str, ...] = ()
    observation_interval_seconds: int = 60
    web_observation_enabled: bool = False
    automation_policy_path: Path | None = None
    patch_inventory_path: Path | None = None
    defense_inventory_path: Path | None = None
    defense_policy_path: Path | None = None
    defense_worker_enabled: bool = False
    vulnerability_scan_enabled: bool = False
    vulnerability_scan_host_ids: tuple[str, ...] = ()
    vulnerability_scan_interval_seconds: int = 3600
    ai_provider: str = "openai"
    vulnerability_webhook_url: str | None = field(default=None, repr=False)
    vulnerability_webhook_key_file: Path | None = field(default=None, repr=False)
    defense_task_watch_enabled: bool = False
    defense_task_watch_host_ids: tuple[str, ...] = ()
    defense_task_watch_interval_seconds: int = 60
    defense_session_enabled: bool = False
    nginx_action_inventory_path: Path | None = None
    container_restart_inventory_path: Path | None = None

    def __post_init__(self) -> None:
        if self.container_restart_inventory_path is not None and (
            not isinstance(self.container_restart_inventory_path, Path)
            or not self.container_restart_inventory_path.is_absolute()
        ):
            raise ValueError("容器重启登记需要部署端绝对路径。")
        if self.nginx_action_inventory_path is not None and (
            not isinstance(self.nginx_action_inventory_path, Path)
            or not self.nginx_action_inventory_path.is_absolute()
        ):
            raise ValueError("Nginx 处置登记需要部署端绝对路径。")
        if (
            self.defense_inventory_path is not None
            and not isinstance(self.defense_inventory_path, Path)
            or self.defense_policy_path is not None
            and not isinstance(self.defense_policy_path, Path)
            or type(self.defense_worker_enabled) is not bool
        ):
            raise ValueError("防护登记和策略只接受部署端路径引用及明确布尔启用项。")
        if self.defense_worker_enabled and (
            self.defense_inventory_path is None or self.defense_policy_path is None
        ):
            raise ValueError("后台防护必须先登记独立身份和部署端策略。")
        if type(self.defense_task_watch_enabled) is not bool:
            raise ValueError("原任务只读跟进必须使用明确布尔启用项。")
        watch_ids = self.defense_task_watch_host_ids
        if (
            type(watch_ids) is not tuple
            or len(watch_ids) > 10
            or any(
                not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in watch_ids
            )
            or len(set(watch_ids)) != len(watch_ids)
            or type(self.defense_task_watch_interval_seconds) is not int
            or not 30 <= self.defense_task_watch_interval_seconds <= 3600
        ):
            raise ValueError("原任务跟进只接受至多十个明确目标和 30 至 3600 秒间隔。")
        if self.defense_task_watch_enabled and (
            not watch_ids or self.defense_inventory_path is None or self.defense_policy_path is None
        ):
            raise ValueError("原任务跟进必须先登记独立身份、部署端策略及明确目标。")
        if type(self.defense_session_enabled) is not bool:
            raise ValueError("单次防护会话必须使用明确布尔启用项。")
        if self.defense_session_enabled and (
            self.defense_inventory_path is None or self.defense_policy_path is None
        ):
            raise ValueError("单次防护会话必须先登记独立身份及部署端策略。")
        if self.ai_provider not in ("openai", "anthropic"):
            raise ValueError("模型提供方只接受 openai 或 anthropic。")
        if self.ai_provider == "anthropic" and (
            self.ai_base_url != ANTHROPIC_BASE_URL
            or self.ai_response_format != "json_prompt"
            or self.ai_token_limit_parameter != "max_tokens"  # noqa: S105 -- API field name.
            or self.ai_thinking_mode != "provider_default"
        ):
            raise ValueError(
                "Claude 原生接口仅接受官方 v1 地址、json_prompt、max_tokens 和 provider_default。"
            )
        if self.ai_key_file is not None and not isinstance(self.ai_key_file, Path):
            raise ValueError("模型凭据文件必须是部署端路径引用。")
        if self.ai_key_file is not None and self.ai_key is not None:
            raise ValueError("模型凭据只能配置环境值或独立文件中的一种。")
        if self.ai_response_format not in {"json_object", "json_schema", "json_prompt"}:
            raise ValueError("模型输出格式配置无效。")
        if self.ai_token_limit_parameter not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("模型令牌限制参数无效。")
        if (
            type(self.ai_max_output_tokens) is not int
            or not 256 <= self.ai_max_output_tokens <= 8192
        ):
            raise ValueError("模型输出令牌上限必须为 256 至 8192。")
        if not isinstance(self.ai_thinking_mode, str) or self.ai_thinking_mode not in {
            "provider_default",
            "enabled",
            "disabled",
        }:
            raise ValueError("模型思考模式只接受 provider_default、enabled 或 disabled。")
        if type(self.observation_enabled) is not bool:
            raise ValueError("持续观察启用项必须为布尔值。")
        if (
            type(self.observation_interval_seconds) is not int
            or not 30 <= self.observation_interval_seconds <= 3600
        ):
            raise ValueError("持续观察间隔必须为 30 至 3600 秒。")
        ids = self.observation_host_ids
        if (
            not isinstance(ids, tuple)
            or len(ids) > 10
            or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("持续观察只接受最多十个唯一的已登记主机标识。")
        if self.observation_enabled and not ids:
            raise ValueError("启用持续观察前必须明确指定主机标识。")
        if type(self.web_observation_enabled) is not bool:
            raise ValueError("Web 持续观察启用项必须为布尔值。")
        if self.web_observation_enabled and not self.observation_enabled:
            raise ValueError("Web 观察需要先启用明确目标的持续观察。")
        if type(self.vulnerability_scan_enabled) is not bool:
            raise ValueError("定期漏洞扫描启用项必须为布尔值。")
        scan_ids = self.vulnerability_scan_host_ids
        if (
            not isinstance(scan_ids, tuple)
            or len(scan_ids) > 10
            or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in scan_ids)
            or len(set(scan_ids)) != len(scan_ids)
        ):
            raise ValueError("定期漏洞扫描需要最多十个唯一的登记主机标识。")
        if self.vulnerability_scan_enabled and not scan_ids:
            raise ValueError("启用定期漏洞扫描前必须明确指定目标。")
        if (
            type(self.vulnerability_scan_interval_seconds) is not int
            or not 300 <= self.vulnerability_scan_interval_seconds <= 86400
        ):
            raise ValueError("定期漏洞扫描间隔必须为 300 至 86400 秒。")
        webhook_configured = (
            self.vulnerability_webhook_url is not None
            or self.vulnerability_webhook_key_file is not None
        )
        if webhook_configured and (
            not self.vulnerability_scan_enabled
            or not isinstance(self.vulnerability_webhook_url, str)
            or not self.vulnerability_webhook_url
            or not isinstance(self.vulnerability_webhook_key_file, Path)
        ):
            raise ValueError("漏洞通知需要启用定期扫描，并同时配置地址和签名密钥文件。")


@dataclass(frozen=True)
class HostConfig:
    public: HostPublic
    key_file: Path
    known_hosts_file: Path
    business_checks: tuple[BusinessCheck, ...] = field(default=(), repr=False)
    ssh_defense_action_ids: tuple[str, ...] = field(default=(), repr=False)
    compose_project: str | None = field(default=None, repr=False)
    container_binding_confirmed: bool = field(default=True, repr=False)
    nginx_scope_digest: str | None = field(default=None, repr=False)
    compose_volume_scope_digest: str | None = field(default=None, repr=False)
    compose_generation_service: str | None = field(default=None, repr=False)
    compose_generation_scope_digest: str | None = field(default=None, repr=False)
    nginx_error_window_enabled: bool = field(default=False, repr=False)


def compose_volume_scope_sha256(project: str) -> str:
    canonical = json.dumps({"compose_project": project, "schema_version": 1}, separators=(",", ":"))
    return hashlib.sha256((canonical + "\n").encode("ascii")).hexdigest()


def compose_generation_scope_sha256(project: str, container: str, service: str) -> str:
    scope = {
        "compose_project": project,
        "container_name": container,
        "schema_version": 1,
        "service": service,
    }
    canonical = json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((canonical + "\n").encode("ascii")).hexdigest()


def validate_ai_url(url: str) -> str:
    """Permit HTTPS providers, or a loopback-only local compatibility service."""
    parsed = urlsplit(url)
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or len(url) > 2048:
        raise ValueError("模型地址格式无效。")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("invalid port")
    except ValueError as error:
        raise ValueError("模型地址端口无效。") from error
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("模型地址不得包含认证信息、查询参数或片段。")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("远程模型地址必须使用 HTTPS；HTTP 仅限本机服务。")
    return url.rstrip("/")


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("OPSARK_DATA_DIR", str(PROJECT_ROOT / "data"))).resolve()
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = os.environ.get("OPSARK_TOKEN", "").strip()
    token_path = data_dir / "access-token"
    if not token:
        if token_path.is_symlink():
            raise ValueError("控制台令牌文件不能是符号链接。")
        try:
            with token_path.open("x", encoding="utf-8") as handle:
                token_path.chmod(0o600)
                handle.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass
        token = token_path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ValueError("控制台令牌至少需要 32 个字符。")
    ai_provider = os.environ.get("OPSARK_AI_PROVIDER", "openai")
    ai_url = os.environ.get("OPSARK_AI_BASE_URL") or None
    ai_key = os.environ.get("OPSARK_AI_KEY") or None
    ai_model = os.environ.get("OPSARK_AI_MODEL") or None
    ai_key_file = os.environ.get("OPSARK_AI_KEY_FILE") or None
    if any((ai_url, ai_key, ai_model, ai_key_file)) and not (
        ai_url and ai_model and (ai_key or ai_key_file)
    ):
        raise ValueError("模型地址、模型名和凭据必须同时配置。")
    try:
        ai_max_tokens = int(os.environ.get("OPSARK_AI_MAX_OUTPUT_TOKENS", "2048"))
    except ValueError:
        raise ValueError("模型输出令牌上限必须为整数。") from None
    if ai_url and ai_provider == "openai":
        ai_url = validate_ai_url(ai_url)
    inventory = os.environ.get("OPSARK_INVENTORY")
    observe_enabled = os.environ.get("OPSARK_OBSERVE_ENABLED", "false").lower().strip()
    if observe_enabled not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_OBSERVE_ENABLED 只接受 true/false 或 1/0。")
    raw_ids = os.environ.get("OPSARK_OBSERVE_HOSTS", "").strip()
    observe_hosts = tuple(item.strip() for item in raw_ids.split(",")) if raw_ids else ()
    web_enabled = os.environ.get("OPSARK_WEB_OBSERVE_ENABLED", "false").lower().strip()
    if web_enabled not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_WEB_OBSERVE_ENABLED 只接受 true/false 或 1/0。")
    try:
        observe_interval = int(os.environ.get("OPSARK_OBSERVE_INTERVAL", "60"))
    except ValueError:
        raise ValueError("OPSARK_OBSERVE_INTERVAL 必须为有效秒数。") from None
    scan_enabled = os.environ.get("OPSARK_VULNERABILITY_SCAN_ENABLED", "false").lower().strip()
    defense_worker = os.environ.get("OPSARK_DEFENSE_WORKER_ENABLED", "false").lower().strip()
    if defense_worker not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_DEFENSE_WORKER_ENABLED 只接受 true/false 或 1/0。")
    defense_session = os.environ.get("OPSARK_DEFENSE_SESSION_ENABLED", "false").lower().strip()
    if defense_session not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_DEFENSE_SESSION_ENABLED 只接受 true/false 或 1/0。")
    task_watch = os.environ.get("OPSARK_DEFENSE_TASK_WATCH_ENABLED", "false").lower().strip()
    if task_watch not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_DEFENSE_TASK_WATCH_ENABLED 只接受 true/false 或 1/0。")
    task_watch_hosts = os.environ.get("OPSARK_DEFENSE_TASK_WATCH_HOSTS", "").strip()
    task_watch_interval = os.environ.get("OPSARK_DEFENSE_TASK_WATCH_INTERVAL", "60").strip()
    if len(task_watch_interval) > 4 or not re.fullmatch(r"[0-9]+", task_watch_interval):
        raise ValueError("OPSARK_DEFENSE_TASK_WATCH_INTERVAL 必须为有效秒数。")
    if scan_enabled not in {"true", "false", "1", "0"}:
        raise ValueError("OPSARK_VULNERABILITY_SCAN_ENABLED 只接受 true/false 或 1/0。")
    scan_hosts = os.environ.get("OPSARK_VULNERABILITY_SCAN_HOSTS", "").strip()
    webhook_url = os.environ.get("OPSARK_VULNERABILITY_WEBHOOK_URL") or None
    webhook_key_file = os.environ.get("OPSARK_VULNERABILITY_WEBHOOK_KEY_FILE") or None
    try:
        scan_interval = int(os.environ.get("OPSARK_VULNERABILITY_SCAN_INTERVAL", "3600"))
    except ValueError:
        raise ValueError("OPSARK_VULNERABILITY_SCAN_INTERVAL 必须为有效秒数。") from None
    return Settings(
        data_dir=data_dir,
        token=token,
        inventory_path=Path(inventory).resolve() if inventory else None,
        ai_base_url=ai_url,
        ai_key=ai_key,
        ai_model=ai_model,
        ai_key_file=Path(ai_key_file).absolute() if ai_key_file else None,
        ai_response_format=os.environ.get("OPSARK_AI_RESPONSE_FORMAT", "json_object"),
        ai_token_limit_parameter=os.environ.get("OPSARK_AI_TOKEN_LIMIT_PARAMETER", "max_tokens"),
        ai_max_output_tokens=ai_max_tokens,
        ai_thinking_mode=os.environ.get("OPSARK_AI_THINKING_MODE", "provider_default"),
        ai_provider=ai_provider,
        observation_enabled=observe_enabled in {"true", "1"},
        observation_host_ids=observe_hosts,
        observation_interval_seconds=observe_interval,
        web_observation_enabled=web_enabled in {"true", "1"},
        automation_policy_path=(
            Path(os.environ["OPSARK_AUTOMATION_POLICY"]).absolute()
            if os.environ.get("OPSARK_AUTOMATION_POLICY")
            else None
        ),
        patch_inventory_path=(
            Path(os.environ["OPSARK_PATCH_INVENTORY"]).absolute()
            if os.environ.get("OPSARK_PATCH_INVENTORY")
            else None
        ),
        defense_inventory_path=(
            Path(os.environ["OPSARK_DEFENSE_INVENTORY"]).absolute()
            if os.environ.get("OPSARK_DEFENSE_INVENTORY")
            else None
        ),
        defense_policy_path=(
            Path(os.environ["OPSARK_DEFENSE_POLICY"]).absolute()
            if os.environ.get("OPSARK_DEFENSE_POLICY")
            else None
        ),
        defense_worker_enabled=defense_worker in {"true", "1"},
        defense_session_enabled=defense_session in {"true", "1"},
        nginx_action_inventory_path=(
            Path(os.environ["OPSARK_NGINX_ACTION_INVENTORY"]).absolute()
            if os.environ.get("OPSARK_NGINX_ACTION_INVENTORY")
            else None
        ),
        container_restart_inventory_path=(
            Path(os.environ["OPSARK_CONTAINER_RESTART_INVENTORY"])
            if os.environ.get("OPSARK_CONTAINER_RESTART_INVENTORY")
            else None
        ),
        defense_task_watch_enabled=task_watch in {"true", "1"},
        defense_task_watch_host_ids=(
            tuple(item.strip() for item in task_watch_hosts.split(",")) if task_watch_hosts else ()
        ),
        defense_task_watch_interval_seconds=int(task_watch_interval),
        vulnerability_scan_enabled=scan_enabled in {"true", "1"},
        vulnerability_scan_host_ids=(
            tuple(item.strip() for item in scan_hosts.split(",")) if scan_hosts else ()
        ),
        vulnerability_scan_interval_seconds=scan_interval,
        vulnerability_webhook_url=webhook_url,
        vulnerability_webhook_key_file=Path(webhook_key_file).absolute()
        if webhook_key_file
        else None,
    )


def load_patch_targets(
    settings: Settings, hosts: dict[str, HostConfig]
) -> "dict[str, PatchTarget]":
    """Repair credentials cannot introduce addresses or identities outside SSH inventory."""
    from opsark.patch_client import PatchTarget

    if settings.patch_inventory_path is None:
        return {}
    path = settings.patch_inventory_path
    if path.is_symlink() or not path.is_file():
        raise ValueError("修复登记需要部署端普通 JSON 文件。")
    with path.open("rb") as handle:
        raw = handle.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("修复登记超过大小限制。")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("修复登记字段不能重复。")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "targets"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["targets"], dict)
        or len(value["targets"]) > 10
    ):
        raise ValueError("修复登记结构不符合约定。")
    targets = {}
    for host_id, record in value["targets"].items():
        if (
            host_id not in hosts
            or not isinstance(record, dict)
            or set(record) != {"key_file", "policy_digest"}
        ):
            raise ValueError("修复目标必须来自既有 SSH 登记且只能引用独立凭据。")
        raw_key = record["key_file"]
        if not isinstance(raw_key, str) or len(raw_key) > 1024:
            raise ValueError("修复密钥需要绝对文件路径。")
        key = Path(raw_key)
        if not key.is_absolute() or key.is_symlink() or not key.is_file():
            raise ValueError("修复密钥需要已有的绝对普通文件路径。")
        targets[host_id] = PatchTarget(hosts[host_id], key, record["policy_digest"])
    return targets


def _text(record: dict, key: str, default: str | None = None) -> str:
    value = record.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"主机登记字段 {key} 需要非空文本。")
    return value.strip()


def _port(record: dict, key: str, default: int) -> int:
    value = record.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"主机登记字段 {key} 必须是有效端口。")
    return value


def _load_business_checks(
    record: dict, username: str, health_checks: list[HealthCheck]
) -> tuple[BusinessCheck, ...]:
    raw = record.get("business_checks", [])
    if not isinstance(raw, list) or len(raw) > 3:
        raise ValueError("每台主机最多登记三项业务就绪检查。")
    if raw and username != "opsark-readonly":
        raise ValueError("业务就绪检查需要专用的 opsark-readonly SSH 账号。")
    try:
        checks = tuple(BusinessCheck.model_validate(item) for item in raw)
    except ValidationError:
        raise ValueError("业务就绪登记字段不符合约定。") from None
    if len({check.id for check in checks}) != len(checks):
        raise ValueError("业务就绪检查标识不能重复。")
    endpoints = {(check.domain.lower(), check.port, check.path) for check in health_checks}
    for check in checks:
        endpoint = (check.domain.lower(), check.port, check.path)
        if endpoint in endpoints:
            raise ValueError("业务就绪路径不能重复登记或用于旧版站点正文采集。")
        endpoints.add(endpoint)
    return checks


def _load_defense_action_ids(
    record: dict, username: str, address: str, port: int
) -> tuple[str, ...]:
    values = record.get("ssh_defense_action_ids", [])
    if (
        not isinstance(values, list)
        or len(values) > 8
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value)
            for value in values
        )
        or len(set(values)) != len(values)
    ):
        raise ValueError("SSH 防护查询最多登记八个不同的动作编号。")
    if values and (username, address, port) != ("opsark-readonly", "198.18.241.2", 22423):
        raise ValueError("SSH 防护查询只接受已限定的隔离只读监听器。")
    return tuple(values)


def load_hosts(settings: Settings) -> dict[str, HostConfig]:
    if settings.inventory_path is None:
        return {}
    with settings.inventory_path.open("rb") as handle:
        inventory = tomllib.load(handle)
    credentials = inventory.get("credentials", {})
    records = inventory.get("hosts", [])
    if not isinstance(credentials, dict) or not isinstance(records, list):
        raise ValueError("主机清单结构不正确。")
    hosts: dict[str, HostConfig] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("主机登记需要对象结构。")
        host_id = _text(record, "id")
        container = _text(record, "container_name", "api")
        username = _text(record, "username", "opsark-readonly")
        address = _text(record, "address")
        port = _port(record, "port", 22)
        site = _text(record, "site_domain")
        if not IDENTIFIER.fullmatch(host_id) or not IDENTIFIER.fullmatch(container):
            raise ValueError("主机或容器标识包含不支持的字符。")
        if host_id in hosts:
            raise ValueError("主机标识不能重复。")
        if not USERNAME.fullmatch(username) or username == "root":
            raise ValueError("请使用专用的非 root SSH 账号。")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError("当前 SSH 采集仅接受 IP 地址，避免 DNS 解析超出连接预算。") from None
        if not DOMAIN.fullmatch(site):
            raise ValueError("网站域名格式不正确。")
        credential = credentials.get(_text(record, "credential"))
        if not isinstance(credential, dict):
            raise ValueError("主机引用的凭据未登记。")
        base = settings.inventory_path.parent
        key = (base / _text(credential, "key_file")).resolve()
        known_hosts = (base / _text(credential, "known_hosts_file")).resolve()
        if not key.is_file() or not known_hosts.is_file():
            raise ValueError("凭据引用需要已有的私钥及已核验的可信主机文件。")
        raw_checks = record.get("health_checks", [])
        if not isinstance(raw_checks, list):
            raise ValueError("站点检查需要列表结构。")
        health_checks = [HealthCheck.model_validate(item) for item in raw_checks]
        business_checks = _load_business_checks(record, username, health_checks)
        defense_actions = _load_defense_action_ids(record, username, address, port)
        compose_project = record.get("compose_project")
        if compose_project is not None and (
            type(compose_project) is not str or COMPOSE_PROJECT.fullmatch(compose_project) is None
        ):
            raise ValueError("Compose 发现只接受一个明确登记的安全项目标识。")
        nginx_scope = record.get("nginx_dependency_scope_digest")
        log_window = record.get("nginx_error_window_enabled", False)
        if type(log_window) is not bool or (
            log_window and (username != "opsark-readonly" or not valid_site(site))
        ):
            raise ValueError("Nginx 日志窗口需要专用只读账号和已登记的具体站点域名。")
        compose_volume_scope = record.get("compose_volume_scope_digest")
        disk_scope = record.get("disk_reclaim_scope_digest")
        if disk_scope is not None and (
            type(disk_scope) is not str
            or re.fullmatch(r"[0-9a-f]{64}", disk_scope) is None
            or username != "opsark-readonly"
        ):
            raise ValueError("磁盘元数据证据需要部署端范围摘要和专用只读账号。")
        if nginx_scope is not None and (
            type(nginx_scope) is not str
            or re.fullmatch(r"[0-9a-f]{64}", nginx_scope) is None
            or compose_project is None
            or username != "opsark-readonly"
        ):
            raise ValueError("Nginx 依赖发现需要部署端范围摘要、授权 Compose 项目和专用只读账号。")
        if compose_volume_scope is not None and (
            type(compose_volume_scope) is not str
            or compose_project is None
            or username != "opsark-readonly"
            or compose_volume_scope != compose_volume_scope_sha256(compose_project)
        ):
            raise ValueError("Compose 卷观察需要部署端范围摘要、授权项目和专用只读账号。")
        container_binding_confirmed = record.get("container_binding_confirmed", True)
        if type(container_binding_confirmed) is not bool or (
            not container_binding_confirmed and compose_project is None
        ):
            raise ValueError("待确认容器需要明确登记的 Compose 发现范围。")
        generation_service = record.get("compose_generation_service")
        generation_scope = record.get("compose_generation_scope_digest")
        if (generation_service is not None or generation_scope is not None) and (
            type(generation_service) is not str
            or IDENTIFIER.fullmatch(generation_service) is None
            or type(generation_scope) is not str
            or compose_project is None
            or username != "opsark-readonly"
            or not container_binding_confirmed
            or generation_scope
            != compose_generation_scope_sha256(compose_project, container, generation_service)
        ):
            raise ValueError("Compose 代次观察需要部署端范围摘要、确认的容器和服务及专用只读账号。")
        with known_hosts.open("rb") as handle:
            trust_digest = hashlib.file_digest(handle, "sha256").hexdigest()
        config_path = record.get("nginx_config_path")
        if config_path is not None and not isinstance(config_path, str):
            raise ValueError("配置摘要路径需要文本。")
        public = HostPublic(
            id=host_id,
            name=_text(record, "name", host_id),
            address=address,
            port=port,
            username=username,
            site_domain=site,
            container_name=container,
            expected_upstream_port=_port(record, "expected_upstream_port", 8081),
            source="ssh",
            health_checks=health_checks,
            nginx_config_path=config_path,
            trusted_hosts_digest=trust_digest,
            web_profile_digest=record.get("web_profile_digest"),
            disk_reclaim_scope_digest=disk_scope,
        )
        commands_for_health(public)
        if public.nginx_config_path:
            config_hash_command(public.nginx_config_path)
        hosts[host_id] = HostConfig(
            public=public,
            key_file=key,
            known_hosts_file=known_hosts,
            business_checks=business_checks,
            ssh_defense_action_ids=defense_actions,
            compose_project=compose_project,
            container_binding_confirmed=container_binding_confirmed,
            nginx_scope_digest=nginx_scope,
            compose_volume_scope_digest=compose_volume_scope,
            compose_generation_service=generation_service,
            compose_generation_scope_digest=generation_scope,
            nginx_error_window_enabled=log_window,
        )
    return hosts
