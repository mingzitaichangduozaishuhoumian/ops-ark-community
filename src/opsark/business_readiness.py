"""Verify registered business routes through the target's private receipt protocol."""

import hashlib
import json
import re
import shlex
from typing import Literal

from opsark.collector import collect_business_receipts, collect_registered_connection
from opsark.config import HostConfig
from opsark.models import BusinessCheck, CheckResult, StrictModel

ReadinessStatus = Literal["passed", "failed", "inconclusive", "uncovered"]
_RECEIPT = re.compile(
    r"OPSARK_HTTP_READINESS_V1 ([2-5][0-9]{2}) (match|status_mismatch|body_mismatch)\n"
)


class BusinessCheckResult(StrictModel):
    id: str
    status: ReadinessStatus
    http_status: int | None = None
    status_matches: bool | None = None
    body_matches: bool | None = None


class BusinessReadiness(StrictModel):
    host_id: str
    status: ReadinessStatus
    checks: list[BusinessCheckResult]


def business_profile_digest(host: HostConfig) -> str:
    """Bind one recheck to the exact private registration used for collection."""
    profile = [check.model_dump(mode="json") for check in host.business_checks]
    canonical = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"opsark-business-profile-v1\0" + canonical).hexdigest()


def commands_for_business(host: HostConfig) -> dict[str, str]:
    """Build exact forced-command policy entries for the confirmed registered probes."""
    return {
        "business_" + check.id: shlex.join(
            [
                "timeout",
                "-k",
                "1s",
                "5s",
                "/usr/bin/python3",
                "-I",
                "-B",
                "/usr/local/libexec/opsark-http-readiness",
                check.domain,
                str(check.port),
                check.path,
                str(check.expected_status),
                check.expected_body_sha256,
            ]
        )
        for check in host.business_checks
        if check.read_only_confirmed
    }


def _evaluate(check: BusinessCheck, receipt: CheckResult | None) -> BusinessCheckResult:
    if not check.read_only_confirmed:
        return BusinessCheckResult(id=check.id, status="uncovered")
    match = None
    if (
        receipt is not None
        and receipt.status == "ok"
        and receipt.exit_code == 0
        and not receipt.truncated
        and not receipt.stderr
    ):
        match = _RECEIPT.fullmatch(receipt.stdout)
    if match is None:
        return BusinessCheckResult(id=check.id, status="inconclusive")

    code, outcome = int(match[1]), match[2]
    status_matches = code == check.expected_status
    if status_matches == (outcome == "status_mismatch"):
        return BusinessCheckResult(id=check.id, status="inconclusive")
    return BusinessCheckResult(
        id=check.id,
        status="passed" if outcome == "match" else "failed",
        http_status=code,
        status_matches=status_matches,
        body_matches=(outcome == "match") if status_matches else None,
    )


def run_business_readiness(host: HostConfig) -> BusinessReadiness:
    """Return derived check states with no investigation, model calls or storage."""
    receipts = collect_business_receipts(host, commands_for_business(host))
    return _project_readiness(host, receipts)


def run_access_readiness(host: HostConfig) -> tuple[bool, BusinessReadiness]:
    """Bind management verification and registered business evidence to one session."""
    authenticated, receipts = collect_registered_connection(
        host, commands_for_business(host), output_limit=96
    )
    return authenticated, _project_readiness(host, receipts if authenticated else {})


def _project_readiness(host: HostConfig, receipts: dict[str, CheckResult]) -> BusinessReadiness:
    results = [
        _evaluate(check, receipts.get("business_" + check.id)) for check in host.business_checks
    ]
    states = {result.status for result in results}
    status: ReadinessStatus = "uncovered"
    for possible in ("failed", "inconclusive", "uncovered", "passed"):
        if possible in states:
            status = possible
            break
    return BusinessReadiness(host_id=host.public.id, status=status, checks=results)
