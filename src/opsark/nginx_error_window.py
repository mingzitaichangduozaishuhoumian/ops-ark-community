"""Decode the fixed SSH log metadata receipt before evidence enters the report."""

import json
import re
from datetime import UTC, datetime, timedelta

from opsark.models import CheckResult, NginxErrorWindow

CHECK = "nginx_error_window"
SCHEMA = "opsark-nginx-error-window/v1"
_UTC_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_COMMAND = "timeout -k 1s 5s /usr/bin/python3 -I -B /usr/local/libexec/opsark-nginx-error-window"
MAX_RECEIPT = 768


def valid_site(domain: str) -> bool:
    return len(domain) <= 253 and all(_LABEL.fullmatch(label) for label in domain.split("."))


def log_window_command(domain: str) -> str:
    if not valid_site(domain):
        raise ValueError("Nginx log window requires a literal site name")
    return f"{_COMMAND} {domain}"


def _unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Repeated Nginx receipt field")
    return value


def decode_receipt(
    check: CheckResult, start: datetime, finished: datetime
) -> tuple[NginxErrorWindow, bool]:
    """Keep only a closed projection, and flag unexpected output for AI egress."""
    failed = NginxErrorWindow(
        status="inconclusive",
        reason="read_unconfirmed",
        observed_at=finished,
        window_seconds=900,
        matching_refused=None,
        matching_timeout=None,
    )
    if check.status != "ok" or check.exit_code != 0 or check.stderr or check.truncated:
        return failed, bool(check.stdout or check.stderr or check.truncated)
    try:
        raw = check.stdout
        if not raw.isascii() or not 0 < len(raw) <= MAX_RECEIPT or not raw.endswith("\n"):
            raise ValueError
        wire = json.loads(raw, object_pairs_hook=_unique)
        if (
            type(wire) is not dict
            or wire.pop("schema", None) != SCHEMA
            or not isinstance(wire.get("observed_at"), str)
            or not _UTC_STAMP.fullmatch(wire["observed_at"])
        ):
            raise ValueError
        value = NginxErrorWindow.model_validate_json(json.dumps(wire), strict=True)
        if (
            not start - timedelta(seconds=60)
            <= value.observed_at
            <= finished + timedelta(seconds=60)
        ):
            return failed.model_copy(update={"reason": "clock_unconfirmed"}), False
        return value, False
    except (ValueError, RecursionError):
        return failed, bool(check.stdout)


def metadata_line(value: NginxErrorWindow) -> str:
    """Render the same closed fields for both Markdown exports."""
    if value.status == "observed":
        outcome = f"匹配上游连接拒绝 {value.matching_refused} 条、超时 {value.matching_timeout} 条"
    else:
        outcome = {
            "permission_denied": "权限不足",
            "source_missing": "登记日志文件缺失",
            "inconclusive": "日志窗口证据不足",
        }[value.status]
    return (
        f"Nginx 日志窗口（{value.observed_at.astimezone(UTC).isoformat(timespec='seconds')}，"
        f"15 分钟）{outcome}。仅覆盖当前文件中的已识别事件。"
    )
