"""Deployment-confirmed loopback HTTP checks and bounded configuration hashing."""

import re
import shlex

from pydantic import ValidationError

from opsark.models import CheckResult, Collection, HealthCheck, HostPublic, Verification

_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_CONFIG_PATH = re.compile(
    r"/etc/nginx/(?:sites-available|conf\.d)/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z"
)
_HTTP_TAIL = re.compile(r"\nOPSARK_HTTP_STATUS:([0-9]{3})\n\Z")
_WRITE_OUT = r"\nOPSARK_HTTP_STATUS:%{http_code}\n"
MAX_HEALTH_OUTPUT_BYTES = 16_384


def _validated_checks(host: HostPublic) -> list[HealthCheck]:
    """Revalidate copied models before their fields reach a remote command."""
    values = host.health_checks
    if not isinstance(values, list) or len(values) > 3:
        raise ValueError("每台主机最多登记三项站点检查。")
    checks: list[HealthCheck] = []
    ids: set[str] = set()
    for value in values:
        if not isinstance(value, HealthCheck):
            raise ValueError("站点检查配置需要有效的登记结构。")
        try:
            check = HealthCheck.model_validate(value.model_dump(warnings=False), strict=True)
        except ValidationError:
            raise ValueError("站点检查配置未通过安全字段校验。") from None
        if len(check.domain) > 253 or any(
            not _DOMAIN_LABEL.fullmatch(label) for label in check.domain.split(".")
        ):
            raise ValueError("站点 Host 需要有效的 ASCII 域名。")
        if check.id in ids:
            raise ValueError("站点检查标识不能重复。")
        ids.add(check.id)
        checks.append(check)
    return checks


def commands_for_health(host: HostPublic) -> dict[str, str]:
    """Build only confirmed GETs to the SSH target's own IPv4 loopback listener."""
    commands: dict[str, str] = {}
    for check in _validated_checks(host):
        if not check.read_only_confirmed:
            continue
        commands["http_" + check.id] = shlex.join(
            [
                "timeout",
                "-k",
                "1s",
                "5s",
                "/usr/bin/curl",
                "--disable",
                "--silent",
                "--show-error",
                "--globoff",
                "--connect-timeout",
                "2",
                "--max-time",
                "4",
                "--max-filesize",
                "8192",
                "--max-redirs",
                "0",
                "--noproxy",
                "*",
                "--proto",
                "=http",
                "--request",
                "GET",
                "--header",
                "Host: " + check.domain,
                "--header",
                "Accept-Encoding: identity",
                "--write-out",
                _WRITE_OUT,
                "--",
                f"http://127.0.0.1:{check.port}{check.path}",
            ]
        )
    return commands


def config_hash_command(path: str) -> str:
    """Hash one allowlisted ordinary configuration file without returning its contents."""
    if not isinstance(path, str) or ".." in path or not _CONFIG_PATH.fullmatch(path):
        raise ValueError("配置摘要只接受登记 Nginx 目录内的安全单文件路径。")
    script = 'test -f "$1" && test ! -L "$1" && exec sha256sum -- "$1"'
    return shlex.join(["timeout", "-k", "1s", "5s", "sh", "-c", script, "opsark-hash", path])


def _reference(name: str) -> str:
    return "E-" + name.replace("_", "-").upper()


def _evaluate_one(
    config: HealthCheck, result: CheckResult | None, fallback: list[str]
) -> Verification:
    name = f"站点即时检查：{config.id}（{config.domain}）"
    if not config.read_only_confirmed:
        return Verification(
            name=name,
            status="uncovered",
            detail="尚未确认该登记路径无业务写入，本次不运行该项检查。",
        )
    if result is None:
        return Verification(
            name=name,
            status="error",
            detail="未取得该项站点检查结果，不能推断业务状态。",
            evidence_ids=fallback,
        )
    refs = [_reference(result.name)]
    try:
        output_bytes = len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
    except UnicodeEncodeError:
        return Verification(
            name=name,
            status="error",
            detail="检查输出无法按 UTF-8 规范处理，无法核验。",
            evidence_ids=refs,
        )
    if result.truncated or output_bytes > MAX_HEALTH_OUTPUT_BYTES:
        return Verification(
            name=name,
            status="error",
            detail="输出已截断或超出字节预算，无法核验完整状态与正文条件。",
            evidence_ids=refs,
        )
    if (
        result.status != "ok"
        or not isinstance(result.exit_code, int)
        or isinstance(result.exit_code, bool)
        or result.exit_code != 0
    ):
        detail = {
            "permission_denied": "站点检查权限不足，结果未完成。",
            "timeout": "站点检查超时，结果未完成。",
            "unavailable": "站点检查结果尚未取得。",
        }.get(result.status, "站点检查未正常完成，不能推断业务状态。")
        return Verification(name=name, status="error", detail=detail, evidence_ids=refs)
    match = _HTTP_TAIL.search(result.stdout)
    if match is None:
        return Verification(
            name=name,
            status="error",
            detail="缺少有效的最终 HTTP 状态元数据，未采信正文中的状态文字。",
            evidence_ids=refs,
        )
    status = int(match.group(1))
    if not 100 <= status <= 599:
        return Verification(
            name=name,
            status="error",
            detail="HTTP 状态元数据超出有效范围，无法核验。",
            evidence_ids=refs,
        )
    body = result.stdout[: match.start()]
    status_matches = status == config.expected_status
    body_matches = config.expected_body in body
    metadata = {
        "http_status": status,
        "status_matches": status_matches,
        "body_matches": body_matches,
    }
    if not status_matches:
        return Verification(
            name=name,
            status="failed",
            detail=f"实际 HTTP {status} 不符合登记状态；本检查不跟随跳转，不代表已恢复。",
            evidence_ids=refs,
            **metadata,
        )
    if not body_matches:
        return Verification(
            name=name,
            status="failed",
            detail=f"实际 HTTP {status} 符合登记状态，但正文未满足登记条件；未回显响应内容。",
            evidence_ids=refs,
            **metadata,
        )
    return Verification(
        name=name,
        status="passed",
        detail=f"实际 HTTP {status} 与登记正文条件符合；仅为即时检查，不代表完整业务或恢复验收。",
        evidence_ids=refs,
        **metadata,
    )


def evaluate_health(host: HostPublic, collection: Collection) -> list[Verification]:
    """Evaluate complete raw in-memory responses before redaction changes their text.

    Only the derived status and match flags belong in the persisted verification;
    response bodies must still pass the separate evidence redaction boundary.
    """
    if host.id != collection.host_id or host.source != collection.source:
        raise ValueError("站点检查结果的目标或来源与登记主机不一致。")
    checks = _validated_checks(host)
    names = [result.name for result in collection.checks]
    if len(names) != len(set(names)):
        raise ValueError("采集检查标识不能重复。")
    if not checks:
        return [
            Verification(
                name="站点即时检查",
                status="uncovered",
                detail="尚未登记并确认无业务写入的站点检查，本次未运行 HTTP 探测。",
            )
        ]
    results = {result.name: result for result in collection.checks}
    fallback = [_reference("connection")] if "connection" in results else []
    return [_evaluate_one(config, results.get("http_" + config.id), fallback) for config in checks]
