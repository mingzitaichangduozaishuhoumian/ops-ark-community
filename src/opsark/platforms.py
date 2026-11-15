"""Conservative adapter selection; remote metadata is never executed as code."""

import platform
import re
import shlex

from opsark.models import CheckResult, CompatibilityAssessment

FAMILIES = ("ubuntu", "debian")
ARCHITECTURES = ("x86_64", "aarch64")
TOOLS = (
    "cat",
    "timeout",
    "sh",
    "env",
    "uname",
    "systemctl",
    "tail",
    "ss",
    "docker",
    "journalctl",
    "df",
    "nice",
    "du",
    "curl",
    "sha256sum",
    "test",
)
CHECK_TOOLS = {
    "nginx_status": ("systemctl",),
    "nginx_errors": ("tail",),
    "listeners": ("ss",),
    "container_state": ("env", "docker"),
    "container_logs": ("env", "docker"),
    "compose_version": ("env", "docker"),
    "docker_rootful": ("env", "docker"),
    "memory_events": ("journalctl",),
    "ssh_auth": ("journalctl",),
    "disk_bytes": ("df",),
    "disk_inodes": ("df",),
    "disk_directories": ("nice", "du"),
    "nginx_config_hash": ("sh", "test", "sha256sum"),
}


def tools_command() -> str:
    script = (
        "printf 'OPSARK_ARCH=%s\\n' \"$(uname -m)\"; "
        "for tool in " + " ".join(TOOLS) + "; do "
        'if command -v "$tool" >/dev/null 2>&1; then present=1; else present=0; fi; '
        'printf \'OPSARK_TOOL_%s=%s\\n\' "$tool" "$present"; done'
    )
    return "timeout -k 1s 5s sh -c " + shlex.quote(script)


def complete(check: CheckResult | None) -> bool:
    return bool(check and check.status == "ok" and check.exit_code == 0 and not check.truncated)


def os_identity(check: CheckResult | None) -> tuple[str | None, str | None]:
    if not complete(check):
        return None, None
    assert check is not None  # noqa: S101 -- narrowed by complete().
    values = {}
    for key, pattern in (("ID", r"[a-z0-9._-]{1,64}"), ("VERSION_ID", r"[A-Za-z0-9._+-]{1,64}")):
        lines = [line for line in check.stdout.splitlines() if line.startswith(key + "=")]
        if len(lines) > 1:
            return None, None
        if not lines:
            continue
        value = lines[0].split("=", 1)[1]
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not re.fullmatch(pattern, value):
            return None, None
        values[key] = value
    return values.get("ID"), values.get("VERSION_ID")


def tool_identity(check: CheckResult | None) -> tuple[str | None, dict[str, bool]]:
    if not complete(check):
        return None, {}
    assert check is not None  # noqa: S101 -- narrowed by complete().
    lines = check.stdout.splitlines()
    expected = {"OPSARK_ARCH", *("OPSARK_TOOL_" + name for name in TOOLS)}
    parsed = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key not in expected or key in parsed:
            return None, {}
        parsed[key] = value
    if parsed.keys() != expected or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,40}", parsed["OPSARK_ARCH"]
    ):
        return None, {}
    if any(parsed["OPSARK_TOOL_" + name] not in {"0", "1"} for name in TOOLS):
        return None, {}
    return parsed["OPSARK_ARCH"], {name: parsed["OPSARK_TOOL_" + name] == "1" for name in TOOLS}


def assess(checks: list[CheckResult]) -> CompatibilityAssessment:
    by_name = {check.name: check for check in checks}
    os_check = by_name.get("os_release")
    tool_check = by_name.get("platform_tools")
    os_id, version_id = os_identity(os_check)
    architecture, tools = tool_identity(tool_check)
    assessment = CompatibilityAssessment(
        os_id=os_id,
        version_id=version_id,
        architecture=architecture,
        available_tools=[name for name, present in tools.items() if present],
        missing_tools=[name for name, present in tools.items() if not present],
        evidence_ids=[
            ref
            for check, ref in ((os_check, "E-OS-RELEASE"), (tool_check, "E-PLATFORM-TOOLS"))
            if check is not None
        ],
        detail="系统或工具探针不完整，无法确认远端适配；旧快照和回放也可能缺少探针。",
    )
    if os_id is not None and os_id not in FAMILIES:
        assessment.status = "unsupported"
        assessment.detail = "系统不在当前 Ubuntu / Debian 适配范围内，停止环境专属采集。"
    elif os_id in FAMILIES and architecture is not None and architecture not in ARCHITECTURES:
        assessment.status = "unsupported"
        assessment.detail = "目标架构不在当前 x86_64 / aarch64 适配范围内，停止环境专属采集。"
    elif os_id in FAMILIES and architecture in ARCHITECTURES and tools:
        assessment.status = "compatible"
        assessment.adapter = "ubuntu_debian"
        assessment.detail = (
            "已匹配 Ubuntu / Debian 命令适配器；仅表示探针兼容，不代表该版本已通过实机验收。"
            "工具存在不证明权限、服务状态、systemd 或 Docker 模式可用；缺失工具的检查会跳过。"
        )
    return assessment


def required_tools(name: str) -> tuple[str, ...]:
    return ("timeout", *(("curl",) if name.startswith("http_") else CHECK_TOOLS.get(name, ())))


def capabilities() -> dict[str, object]:
    return {
        "controller": {
            "system": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "managed": {
            "profile": "ubuntu_debian",
            "families": list(FAMILIES),
            "architectures": list(ARCHITECTURES),
            "mode": "read_only",
            "preflight": True,
        },
    }
