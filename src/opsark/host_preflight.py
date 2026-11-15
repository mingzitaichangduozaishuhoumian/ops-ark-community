"""Project a bounded, read-only SSH preflight into fixed status fields."""

import json
import re
from datetime import datetime
from typing import Literal

from pydantic import Field

from opsark.collector import collect_ssh_preflight
from opsark.config import HostConfig
from opsark.diagnostics import _df
from opsark.models import CheckResult, CheckStatus, StrictModel
from opsark.platforms import assess, complete

type PreflightStatus = Literal["ready", "needs_attention", "unreachable", "unsupported"]
type PreflightConnection = Literal["ok", "error", "permission_denied", "timeout"]
type PreflightPlatform = Literal["compatible", "unsupported", "unknown"]
type PreflightFamily = Literal["ubuntu", "debian"]
type PreflightArchitecture = Literal["x86_64", "aarch64"]
type PreflightCheckId = Literal[
    "os_release",
    "platform_tools",
    "nginx_status",
    "container_state",
    "disk_bytes",
    "disk_inodes",
    "compose_version",
    "docker_rootful",
]
type PreflightCheckStatus = CheckStatus | Literal["inactive"]
type PreflightCheckReason = Literal[
    "registration_unconfirmed",
    "plugin_unavailable",
    "unsupported_version",
    "rootless_unsupported",
    "engine_unsupported",
    "invalid_output",
    "output_truncated",
    "permission_denied",
    "timeout",
    "probe_unavailable",
    "probe_failed",
    "policy_refused",
]
type PreflightTool = Literal["cat", "timeout", "sh", "uname", "systemctl", "env", "docker", "df"]

_CHECKS: tuple[PreflightCheckId, ...] = (
    "os_release",
    "platform_tools",
    "nginx_status",
    "container_state",
    "disk_bytes",
    "disk_inodes",
    "compose_version",
    "docker_rootful",
)
_TOOLS: tuple[PreflightTool, ...] = (
    "cat",
    "timeout",
    "sh",
    "uname",
    "systemctl",
    "env",
    "docker",
    "df",
)
_FAMILIES: dict[str, PreflightFamily] = {"ubuntu": "ubuntu", "debian": "debian"}
_ARCHITECTURES: dict[str, PreflightArchitecture] = {"x86_64": "x86_64", "aarch64": "aarch64"}
_CONNECTION_ERRORS: dict[str, PreflightConnection] = {
    "error": "error",
    "permission_denied": "permission_denied",
    "timeout": "timeout",
}
_CONTAINER_INACTIVE = {"created", "paused", "restarting", "removing", "exited", "dead"}
_NGINX_INACTIVE = {"inactive", "failed", "activating", "deactivating"}
_COMPOSE_UNAVAILABLE = {
    "docker: 'compose' is not a docker command.",
    "docker: 'compose' is not a docker command.\nSee 'docker --help'",
    "docker: unknown command: docker compose",
    "docker: unknown command: docker compose\n\nRun 'docker --help' for more information",
}


class HostPreflightCheck(StrictModel):
    id: PreflightCheckId
    status: PreflightCheckStatus
    reason: PreflightCheckReason | None = None


class HostPreflight(StrictModel):
    host_id: str
    status: PreflightStatus
    connection: PreflightConnection
    platform: PreflightPlatform
    os_family: PreflightFamily | None
    architecture: PreflightArchitecture | None
    missing_tools: list[PreflightTool] = Field(max_length=len(_TOOLS))
    checks: list[HostPreflightCheck] = Field(min_length=len(_CHECKS), max_length=len(_CHECKS))
    checked_at: datetime
    duration_ms: int = Field(ge=0)


def _clean_output(check: CheckResult) -> bool:
    return bool(check.stdout.strip() and not check.stderr.strip() and "\ufffd" not in check.stdout)


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("Duplicate container state field")
    return values


def _invalid_constant(_value: str) -> None:
    raise ValueError("Invalid container state value")


def _container_status(raw: str, expected: str) -> PreflightCheckStatus:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        return "error"
    if not isinstance(value, dict) or value.get("Name") != "/" + expected:
        return "error"
    state = value.get("State")
    status = state.get("Status") if isinstance(state, dict) else None
    if status == "running":
        return "ok"
    if isinstance(status, str) and status in _CONTAINER_INACTIVE:
        return "inactive"
    return "error"


def _capability(
    check: CheckResult | None,
) -> tuple[PreflightCheckStatus, PreflightCheckReason | None]:
    """Project fixed Docker metadata, never its raw version/error text."""
    if check is None:
        return "unavailable", "probe_unavailable"
    if check.truncated:
        return "error", "output_truncated"
    if check.status != "ok":
        if (
            check.status == "error"
            and check.exit_code == 126
            and not check.stdout.strip()
            and check.stderr.strip() == "OpsArk restricted collector refused this request."
        ):
            return "error", "policy_refused"
        reasons: dict[str, PreflightCheckReason] = {
            "permission_denied": "permission_denied",
            "timeout": "timeout",
            "unavailable": "probe_unavailable",
        }
        unavailable = (
            check.name == "compose_version"
            and check.status == "error"
            and check.exit_code == 1
            and not check.stdout.strip()
            and check.stderr.strip() in _COMPOSE_UNAVAILABLE
        )
        return check.status, reasons.get(
            check.status, "plugin_unavailable" if unavailable else "probe_failed"
        )
    if check.exit_code != 0:
        return "error", "probe_failed"
    if not _clean_output(check):
        return "error", "invalid_output"
    if check.name == "compose_version":
        if len(check.stdout.strip()) > 128:
            return "error", "invalid_output"
        match = re.fullmatch(
            r"v?(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})"
            r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
            # Ubuntu package builds can append ~YY.MM.revision to build metadata.
            r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*(?:~[0-9]{2}\.[0-9]{2}\.[0-9]+)?)?",
            check.stdout.strip(),
        )
        if match is None:
            return "error", "invalid_output"
        return ("ok", None) if match.group(1) == "2" else ("error", "unsupported_version")
    try:
        value = json.loads(
            check.stdout, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant
        )
    except (ValueError, RecursionError):
        return "error", "invalid_output"
    if type(value) is not dict or set(value) != {"OSType", "SecurityOptions"}:
        return "error", "invalid_output"
    if value["OSType"] != "linux":
        return "error", "engine_unsupported"
    options = value["SecurityOptions"]
    if (
        type(options) is not list
        or len(options) > 32
        or not all(
            type(item) is str
            and re.fullmatch(
                r"(?:name=)?[a-z][a-z0-9_-]{0,31}(?:,[a-z][a-z0-9_-]{0,31}=[a-z0-9_.-]{1,64})*",
                item,
            )
            for item in options
        )
    ):
        return "error", "invalid_output"
    if any(item.split(",", 1)[0] in {"rootless", "name=rootless"} for item in options):
        return "error", "rootless_unsupported"
    return "ok", None


def _check_status(
    check: CheckResult,
    *,
    os_identified: bool,
    tools_identified: bool,
    container: str,
) -> PreflightCheckStatus:
    if (
        check.name == "nginx_status"
        and check.status == "error"
        and check.exit_code == 3
        and not check.truncated
        and _clean_output(check)
        and check.stdout.strip() in _NGINX_INACTIVE
    ):
        return "inactive"
    if check.status != "ok":
        return check.status
    if not complete(check) or not _clean_output(check):
        return "error"
    match check.name:
        case "os_release":
            return "ok" if os_identified else "error"
        case "platform_tools":
            return "ok" if tools_identified else "error"
        case "nginx_status":
            return "ok" if check.stdout.strip() == "active" else "error"
        case "container_state":
            return _container_status(check.stdout, container)
        case "disk_bytes" | "disk_inodes":
            return "ok" if _df(check.stdout, inode=check.name == "disk_inodes") else "error"
    return "unavailable"


def run_host_preflight(host: HostConfig) -> HostPreflight:
    """Confirm pinned collection plus complete rootful Compose v2 probe results."""
    collection = collect_ssh_preflight(host)
    by_name = {check.name: check for check in collection.checks}
    connection: PreflightConnection = "ok"
    connection_result = by_name.pop("connection", None)
    if connection_result is not None:
        connection = _CONNECTION_ERRORS.get(connection_result.status, "error")
    elif collection.source != "ssh" or collection.host_id != host.public.id or not by_name:
        connection = "error"
    if connection != "ok":
        by_name.clear()
    elif len(by_name) != len(collection.checks) or not set(by_name).issubset(_CHECKS):
        # The fixed sequence cannot produce extra or duplicate check results.
        by_name.clear()

    assessment = assess([check for check in by_name.values() if _clean_output(check)])
    missing = [tool for tool in _TOOLS if tool in assessment.missing_tools]
    results = [
        HostPreflightCheck(
            id=name,
            status=(
                _check_status(
                    check,
                    os_identified=assessment.os_id is not None,
                    tools_identified=assessment.architecture is not None,
                    container=host.public.container_name,
                )
                if (check := by_name.get(name)) is not None
                else "unavailable"
            ),
        )
        for name in _CHECKS
        if name not in {"compose_version", "docker_rootful"}
    ]
    for name in ("compose_version", "docker_rootful"):
        state, reason = _capability(by_name.get(name))
        results.append(HostPreflightCheck(id=name, status=state, reason=reason))
    if not host.container_binding_confirmed:
        results = [
            HostPreflightCheck(
                id="container_state", status="unavailable", reason="registration_unconfirmed"
            )
            if check.id == "container_state"
            else check
            for check in results
        ]
    status: PreflightStatus = "needs_attention"
    if connection != "ok":
        status = "unreachable"
    elif assessment.status == "unsupported":
        status = "unsupported"
    elif (
        assessment.status == "compatible" and not missing and all(c.status == "ok" for c in results)
    ):
        status = "ready"
    return HostPreflight(
        host_id=host.public.id,
        status=status,
        connection=connection,
        platform=assessment.status,
        os_family=_FAMILIES.get(assessment.os_id or ""),
        architecture=_ARCHITECTURES.get(assessment.architecture or ""),
        missing_tools=missing,
        checks=results,
        checked_at=collection.started_at,
        duration_ms=collection.duration_ms,
    )
