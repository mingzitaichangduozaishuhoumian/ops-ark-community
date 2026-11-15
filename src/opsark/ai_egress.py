"""Fail closed at the provider boundary. Local evidence is never a prompt format."""

import importlib
import json
import math
import re
import unicodedata
from typing import Literal
from urllib.parse import urlsplit

from opsark.redaction import redact

MAX_REQUEST_BYTES = 65_536
MAX_SOURCE_CHARS = 4_194_304
MAX_SOURCE_NODES = 250_000
ROUTES = {
    "diagnosis": "opsark.ai",
    "security": "opsark.security_ai",
    "vulnerability": "opsark.vulnerability_ai",
    "focused": "opsark.vulnerability_ai_focus",
    "ssh_defense": "opsark.defense_ai",
}
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}\Z")
SENSITIVE_KEY = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "authorization",
        "bearertoken",
        "clientsecret",
        "cookie",
        "credential",
        "credentials",
        "databasecontent",
        "databasedump",
        "databaseraw",
        "databaserows",
        "databaseurl",
        "dbdump",
        "dbrows",
        "idtoken",
        "password",
        "passwd",
        "pwd",
        "privatekey",
        "proxyauthorization",
        "rawdatabase",
        "rawrows",
        "rawsql",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessiontoken",
        "setcookie",
        "sqldump",
        "sshkey",
        "token",
    }
)
SENSITIVE_TEXT = re.compile(
    r"(?im)\[REDACTED(?:_[A-Z]+)?\]|-----BEGIN [^\r\n-]{0,80}PRIVATE KEY-----|"
    r"\b(?:authorization|proxy-authorization)\s*:\s*(?:basic|bearer)\b|"
    r"\b(?:private[_-]?key|database[_-]?url|client[_-]?secret|session[_-]?token)\s*[:=]|"
    r"\b(?:sk_[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"AIza[A-Za-z0-9_-]{20,}|ASIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b|"
    r"SQLite format 3|PGDMP|\b(?:MySQL|MariaDB|PostgreSQL) (?:database )?dump\b|"
    r"\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\b|"
    r"\b(?:INSERT|REPLACE)\s+INTO\b[^;]{1,2000}\bVALUES\s*\(|"
    r"\bCOPY\s+[^;]{1,500}\bFROM\s+STDIN\b|"
    r"\bSELECT\s+[^;]{1,500}\bFROM\s+[\w\"`\[]"
)


class AIEgressBlocked(ValueError):
    """The provider was not contacted. Messages and codes contain no input values."""

    messages = {
        "sensitive_content": "AI 外发已拦截：发现敏感内容。",
        "unclassified_payload": "AI 外发已拦截：内容不符合该入口的字段白名单。",
        "input_budget_exceeded": "AI 外发已拦截：输入超出本地校验范围。",
    }

    def __init__(
        self,
        code: Literal[
            "sensitive_content", "unclassified_payload", "input_budget_exceeded"
        ] = "unclassified_payload",
    ):
        self.code = code
        super().__init__(self.messages[code])


def _walk_json(value, *, text_check=None, key_check=None):
    """Bound and check JSON types before encoding can silently coerce them."""
    characters = nodes = 0

    def check_text(item):
        nonlocal characters
        characters += len(item)
        if characters > MAX_SOURCE_CHARS:
            raise AIEgressBlocked("input_budget_exceeded")
        if text_check is not None:
            text_check(item)

    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_SOURCE_NODES or depth > 20:
            raise AIEgressBlocked("input_budget_exceeded")
        if type(item) is str:
            check_text(item)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise AIEgressBlocked()
                check_text(key)
                if key_check is not None:
                    key_check(key)
                walk(child, depth + 1)
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)
        elif (
            item is not None
            and type(item) not in {bool, int}
            and (type(item) is not float or not math.isfinite(item))
        ):
            raise AIEgressBlocked()

    walk(value, 0)


def guard_source(value, settings):
    """Inspect for secret/SQL signals before local projection can hide them."""
    known = tuple(
        unicodedata.normalize("NFKC", item)
        for item in (settings.token, settings.ai_key)
        if isinstance(item, str) and item
    )

    def check_text(item):
        text = unicodedata.normalize("NFKC", item)
        if (
            any(text == secret or len(secret) >= 8 and secret in text for secret in known)
            or SENSITIVE_TEXT.search(text)
            or redact(text) != text
        ):
            raise AIEgressBlocked("sensitive_content")

    def check_key(key):
        normalized = unicodedata.normalize("NFKC", key).lower()
        if re.sub(r"[^a-z0-9]", "", normalized) in SENSITIVE_KEY:
            raise AIEgressBlocked("sensitive_content")

    _walk_json(value, text_check=check_text, key_check=check_key)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AIEgressBlocked()
        result[key] = value
    return result


def _constant(_value):
    raise AIEgressBlocked()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def guard_request(body, settings, route):
    """Check the exact normalized body and return a detached copy for transport."""
    if type(route) is not str or route not in ROUTES or type(body) is not dict:
        raise AIEgressBlocked()
    console_token, provider_key = settings.token, settings.ai_key
    if (
        console_token
        and provider_key
        and (
            console_token == provider_key
            or len(console_token) >= 8
            and console_token in provider_key
        )
    ):
        raise AIEgressBlocked("sensitive_content")
    limit_key = settings.ai_token_limit_parameter
    keys = {"model", "messages", limit_key}
    if settings.ai_response_format != "json_prompt":
        keys.add("response_format")
    if settings.ai_thinking_mode != "provider_default":
        keys.add("thinking")
    if set(body) != keys:
        raise AIEgressBlocked()
    try:
        _walk_json(body)
        encoded = _encoded(body)
        if len(encoded) > MAX_REQUEST_BYTES:
            raise AIEgressBlocked("input_budget_exceeded")
        body = json.loads(encoded)
        if (
            type(body["model"]) is not str
            or not MODEL.fullmatch(body["model"])
            or body["model"] != settings.ai_model
            or type(body[limit_key]) is not int
            or not 1 <= body[limit_key] <= settings.ai_max_output_tokens
            or "thinking" in keys
            and body["thinking"] != {"type": settings.ai_thinking_mode}
        ):
            raise AIEgressBlocked()
        messages = body["messages"]
        if (
            type(messages) is not list
            or len(messages) != 2
            or any(
                not isinstance(message, dict)
                or set(message) != {"role", "content"}
                or message["role"] != role
                or type(message["content"]) is not str
                for message, role in zip(messages, ("system", "user"), strict=True)
            )
        ):
            raise AIEgressBlocked()
        summary = json.loads(
            messages[1]["content"], object_pairs_hook=_pairs, parse_constant=_constant
        )
        endpoint = settings.ai_base_url
        if not isinstance(endpoint, str) or "%" in endpoint:
            raise AIEgressBlocked()
        guard_source([summary, body["model"], endpoint, urlsplit(endpoint).hostname], settings)
        contract = importlib.import_module(ROUTES[route])
        contract.validate_egress(summary)
        if messages[0]["content"] != contract.egress_system(summary) or _encoded(
            body.get("response_format")
        ) != _encoded(contract.egress_format(settings)):
            raise AIEgressBlocked()
        messages[1]["content"] = _encoded(summary)
        return body
    except AIEgressBlocked:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        raise AIEgressBlocked() from None
