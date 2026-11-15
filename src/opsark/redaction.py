"""Reduce credential exposure before evidence is persisted or explained."""

import re

from opsark.models import Collection

MAX_TEXT = 16_384
REDACTED = "[REDACTED]"
PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|\Z)")
HEADERS = re.compile(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+")
FIELDS = re.compile(
    r"(?i)([\"']?(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"token|secret|client[_-]?secret)[\"']?\s*[:=]\s*)"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&\"'}]+)"
)
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
KNOWN_KEYS = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|AKIA[A-Z0-9]{16})\b")
URL_CREDENTIAL = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s/@]+@", re.IGNORECASE)
QUERY = re.compile(r"([a-z][a-z0-9+.-]*://[^\s?]+)\?[^\s\"'<>]+", re.IGNORECASE)


def redact(text: str) -> str:
    result = PEM.sub(REDACTED, text)
    result = HEADERS.sub(lambda match: match.group(1) + ": " + REDACTED, result)

    def replace_field(match: re.Match) -> str:
        value = match.group(2)
        quote = value[0] if value.startswith(('"', "'")) else ""
        return match.group(1) + quote + REDACTED + quote

    result = FIELDS.sub(replace_field, result)
    result = BEARER.sub("Bearer " + REDACTED, result)
    result = KNOWN_KEYS.sub(REDACTED, result)
    result = URL_CREDENTIAL.sub(r"\1" + REDACTED + "@", result)
    return QUERY.sub(r"\1?[REDACTED_QUERY]", result)


def sanitize_collection(collection: Collection) -> Collection:
    checks = []
    for check in collection.checks:
        stdout = redact(check.stdout)
        stderr = redact(check.stderr)
        checks.append(
            check.model_copy(
                update={
                    "stdout": stdout[:MAX_TEXT],
                    "stderr": stderr[:MAX_TEXT],
                    "truncated": check.truncated
                    or len(stdout) > MAX_TEXT
                    or len(stderr) > MAX_TEXT,
                }
            )
        )
    return collection.model_copy(update={"checks": checks})
