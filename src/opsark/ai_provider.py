"""Single-attempt provider requests with bounded, file-backed credentials."""

import asyncio
import hashlib
import json
import os
import stat
from dataclasses import replace
from urllib.parse import urlsplit

import httpx

from opsark.ai_dispatch import verify_current_dispatch
from opsark.ai_egress import MODEL, AIEgressBlocked, guard_request, guard_source
from opsark.config import ANTHROPIC_BASE_URL, Settings, validate_ai_url
from opsark.redaction import redact

ANTHROPIC_VERSION = "2023-06-01"


class ProviderError(ValueError):
    """Sanitized provider failure; never carries response bodies or credentials."""


class ProviderRequestUnknown(ProviderError):
    """The provider may have processed the one request; it must not be replayed."""


class ProviderRefusal(ProviderError):
    pass


class ProviderResponseInvalid(ProviderError):
    """A fixed outer-response failure, separate from local request/config errors."""

    REASONS = {
        "provider_json_invalid": "模型服务响应不是有效的 JSON 对象。",
        "provider_response_too_large": "模型响应超出大小限制。",
        "provider_object_invalid": "模型响应不是可信对象。",
    }

    def __init__(self, code):
        self.code = code
        self.stage = "provider_response"
        super().__init__(self.REASONS[code])


class ProviderRejected(ProviderError):
    """A safe status code; upstream bodies, headers and credentials are never carried."""

    def __init__(self, status_code: int):
        self.status_code = status_code
        self.failure_kind = {
            401: "provider_authentication_failed",
            403: "provider_access_denied",
            402: "provider_quota_rejected",
            429: "provider_rate_limited",
        }.get(
            status_code,
            "provider_request_rejected" if status_code < 500 else "provider_unavailable",
        )
        super().__init__(f"模型服务拒绝了本次请求（HTTP {status_code}）；没有自动重试。")


def _secret(value):
    if not isinstance(value, str):
        raise ProviderError("模型凭据不可用。")
    value = value.strip()
    if not value or len(value) > 8192 or any(ord(c) < 33 or ord(c) >= 127 for c in value):
        raise ProviderError("模型凭据格式无效。")
    return value


def _safe_model(model, settings):
    if not isinstance(model, str) or not MODEL.fullmatch(model):
        return None
    try:
        guard_source(model, settings)
    except AIEgressBlocked:
        return None
    return model


def _safe_metadata(settings):
    if settings.ai_model is not None and _safe_model(settings.ai_model, settings) is None:
        return replace(settings, ai_model=None)
    return settings


def resolve_ai_settings(settings: Settings) -> Settings:
    settings = _safe_metadata(settings)
    path = settings.ai_key_file
    if path is None:
        if settings.ai_key is None:
            return settings
        try:
            return _safe_metadata(replace(settings, ai_key=_secret(settings.ai_key)))
        except ValueError:
            return replace(settings, ai_key=None)
    try:
        if path.is_symlink():
            raise ProviderError("模型凭据文件不可用。")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        try:
            meta = os.fstat(descriptor)
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_nlink != 1
                or meta.st_size > 8192
                or os.name == "posix"
                and (meta.st_mode & 0o077 or meta.st_uid not in {0, os.geteuid()})
            ):
                raise ProviderError("模型凭据文件权限或类型无效。")
            raw = os.read(descriptor, 8193)
            after = os.fstat(descriptor)
            if (meta.st_size, meta.st_mtime_ns, meta.st_ino) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ino,
            ):
                raise ProviderError("读取模型凭据时文件已变化。")
        finally:
            os.close(descriptor)
        key = _secret(raw.decode("utf-8"))
        # The effective copy is used only for this request, never persisted or returned.
        return _safe_metadata(replace(settings, ai_key_file=None, ai_key=key))
    except (OSError, UnicodeError, ValueError):
        return replace(settings, ai_key_file=None, ai_key=None)


def provider_binding_fields(settings: Settings) -> dict:
    values = {
        "base_url": settings.ai_base_url,
        "model": settings.ai_model,
        "response_format": settings.ai_response_format,
        "token_limit_parameter": settings.ai_token_limit_parameter,
        "max_output_tokens": settings.ai_max_output_tokens,
        "thinking_mode": settings.ai_thinking_mode,
    }
    if settings.ai_provider == "anthropic":
        values["provider_kind"] = "anthropic"
    return values


def provider_fingerprint(settings: Settings) -> str:
    return hashlib.sha256(
        json.dumps(
            provider_binding_fields(settings), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def provider_status(settings: Settings) -> dict:
    effective = resolve_ai_settings(settings)
    missing = []
    for name, value in (
        ("base_url", effective.ai_base_url),
        ("model", effective.ai_model),
        ("credential", effective.ai_key),
    ):
        if not value:
            missing.append(name)
    host = None
    try:
        if effective.ai_base_url:
            host = urlsplit(validate_ai_url(effective.ai_base_url)).hostname
        if effective.ai_key:
            _secret(effective.ai_key)
    except ValueError:
        missing.append("valid_provider_configuration")
    model = effective.ai_model
    if model and (model == effective.ai_key or model == settings.token or redact(model) != model):
        model = None
        missing.append("valid_model_identifier")
    return {
        "configured": not missing,
        "provider_kind": settings.ai_provider,
        "provider_host": host,
        "model_name": model,
        "response_format": settings.ai_response_format,
        "token_limit_parameter": settings.ai_token_limit_parameter,
        "max_output_tokens": settings.ai_max_output_tokens,
        "thinking_mode": settings.ai_thinking_mode,
        "missing": missing,
        "provider_fingerprint": provider_fingerprint(effective) if not missing else None,
    }


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProviderError("模型响应包含重复字段。")
        value[key] = item
    return value


def _constant(_value):
    raise ProviderError("模型响应包含非有限数值。")


def strict_json(value):
    return json.loads(value, object_pairs_hook=_unique, parse_constant=_constant)


def _claude_completion(document, settings):
    invalid = ProviderResponseInvalid("provider_object_invalid")
    if (
        not isinstance(document, dict)
        or document.get("type") != "message"
        or document.get("role") != "assistant"
        or document.get("error")
        or document.get("stop_sequence") is not None
    ):
        raise invalid
    reason = document.get("stop_reason")
    details = document.get("stop_details")
    if reason == "refusal" or isinstance(details, dict) and details.get("type") == "refusal":
        raise ProviderRefusal("模型拒绝了这次分析。")
    if reason not in ("end_turn", "max_tokens") or details is not None:
        raise invalid

    message = {"role": "assistant", "content": ""}
    if reason == "end_turn":
        blocks = document.get("content")
        if (
            not isinstance(blocks, list)
            or not 1 <= len(blocks) <= 16
            or any(
                not isinstance(block, dict)
                or set(block) - {"type", "text", "citations"}
                or block.get("type") != "text"
                or not isinstance(block.get("text"), str)
                or block.get("citations") not in (None, [])
                for block in blocks
            )
        ):
            raise invalid
        message["content"] = "".join(block["text"] for block in blocks)
        if not message["content"].strip():
            raise invalid

    usage = {}
    if isinstance(raw_usage := document.get("usage"), dict):
        for source, target in (
            ("input_tokens", "prompt_tokens"),
            ("output_tokens", "completion_tokens"),
        ):
            tokens = raw_usage.get(source)
            if type(tokens) is int and 0 <= tokens <= 2_000_000:
                usage[target] = tokens
        if len(usage) == 2 and (total := sum(usage.values())) <= 2_000_000:
            usage["total_tokens"] = total
    return {
        "model": _safe_model(document.get("model"), settings),
        "choices": [
            {"finish_reason": "stop" if reason == "end_turn" else "length", "message": message}
        ],
        "usage": usage,
    }


async def _request(body, settings, maximum, seconds):
    async def before_request(_request):
        # The synchronous admission precedes event-loop and client creation.
        # Repeat it at HTTPX's actual request hook so a stop/lease change during
        # those steps cannot begin a provider attempt with stale authority.
        verify_current_dispatch()

    if settings.ai_provider == "anthropic":
        endpoint = ANTHROPIC_BASE_URL + "/messages"
        headers = {"x-api-key": settings.ai_key, "anthropic-version": ANTHROPIC_VERSION}
        body = {
            "model": body["model"],
            "max_tokens": body["max_tokens"],
            "system": body["messages"][0]["content"],
            "messages": [body["messages"][1]],
        }
    else:
        endpoint = validate_ai_url(settings.ai_base_url) + "/chat/completions"
        headers = {"Authorization": "Bearer " + settings.ai_key}
    async with (
        httpx.AsyncClient(
            timeout=seconds,
            follow_redirects=False,
            trust_env=False,
            event_hooks={"request": [before_request]},
        ) as client,
        asyncio.timeout(seconds),
        client.stream(
            "POST",
            endpoint,
            headers=headers,
            json=body,
        ) as response,
    ):
        if not 200 <= response.status_code < 300:
            raise ProviderRejected(response.status_code)
        raw = bytearray()
        async for chunk in response.aiter_bytes(chunk_size=4096):
            if len(raw) + len(chunk) > maximum:
                raise ProviderResponseInvalid("provider_response_too_large")
            raw.extend(chunk)
    try:
        value = strict_json(raw)
    except (ValueError, RecursionError):
        raise ProviderResponseInvalid("provider_json_invalid") from None
    return _claude_completion(value, settings) if settings.ai_provider == "anthropic" else value


def request_document(
    body: dict,
    settings: Settings,
    *,
    route: str,
    max_response_bytes: int = 65_536,
    timeout_seconds: float = 45,
) -> dict:
    effective = resolve_ai_settings(settings)
    if not provider_status(effective)["configured"]:
        raise ProviderError("AI 提供方尚未配置完整。")
    if (
        not isinstance(body, dict)
        or body.get("model") != effective.ai_model
        or not 1024 <= max_response_bytes <= 1_048_576
        or not 0 < timeout_seconds <= 120
    ):
        raise ProviderError("模型请求不符合配置或预算。")
    if "thinking" in body or (
        effective.ai_response_format == "json_prompt" and "response_format" in body
    ):
        raise AIEgressBlocked()
    outgoing = dict(body)
    if effective.ai_thinking_mode != "provider_default":
        outgoing["thinking"] = {"type": effective.ai_thinking_mode}
    limits = [
        outgoing.pop(name) for name in ("max_tokens", "max_completion_tokens") if name in outgoing
    ]
    if len(limits) > 1 or any(type(v) is not int or v < 1 for v in limits):
        raise ProviderError("模型输出预算无效。")
    outgoing[effective.ai_token_limit_parameter] = min(
        effective.ai_max_output_tokens, limits[0] if limits else effective.ai_max_output_tokens
    )
    outgoing = guard_request(outgoing, effective, route)
    encoded = json.dumps(outgoing, allow_nan=False, ensure_ascii=False).encode()
    if len(encoded) > 65_536:
        raise ProviderError("模型输入超出大小限制。")
    verify_current_dispatch()
    try:
        value = asyncio.run(_request(outgoing, effective, max_response_bytes, timeout_seconds))
        if not isinstance(value, dict):
            raise ProviderResponseInvalid("provider_object_invalid")
        return value
    except (TimeoutError, httpx.TransportError):
        raise ProviderRequestUnknown("模型请求结果未知；不会自动重复发送。") from None


def response_metadata(document, settings):
    """Retain only bounded billing/envelope diagnostics, never reasoning or raw text."""
    if not isinstance(document, dict):
        return None
    model = document.get("model")
    if (
        not isinstance(model, str)
        or len(model) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in model)
        or any(secret and secret in model for secret in (settings.ai_key, settings.token))
        or redact(model) != model
    ):
        model = None
    choices = document.get("choices")
    choice = (
        choices[0]
        if isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict)
        else {}
    )
    raw_message = choice.get("message")
    message = raw_message if isinstance(raw_message, dict) else {}
    reason = choice.get("finish_reason")
    content = message.get("content")
    raw_usage = document.get("usage")
    usage = raw_usage if isinstance(raw_usage, dict) else {}
    return {
        "returned_model": model,
        "finish_reason": reason
        if isinstance(reason, str)
        and reason in {"stop", "length", "content_filter", "tool_calls", "function_call"}
        else "unknown",
        "content_bytes": len(content.encode()) if isinstance(content, str) else 0,
        "reasoning_output_present": bool(message.get("reasoning_content")),
        "usage": {
            k: usage[k]
            for k in ("prompt_tokens", "completion_tokens", "total_tokens")
            if type(usage.get(k)) is int and 0 <= usage[k] <= 2_000_000
        },
    }


def completion_text(document: dict) -> str:
    try:
        choices = document["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise ProviderError("模型响应选择数量无效。")
        choice = choices[0]
        message = choice["message"]
        if message.get("refusal"):
            raise ProviderRefusal("模型拒绝了这次分析。")
        if (
            choice.get("finish_reason") != "stop"
            or message.get("tool_calls")
            or message.get("function_call")
            or message.get("role", "assistant") != "assistant"
            or not isinstance(message.get("content"), str)
            or not message["content"].strip()
        ):
            raise ProviderError("模型结果未完成、包含工具调用或没有有效内容。")
        return message["content"]
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise ProviderError("模型响应结构无效。") from error
