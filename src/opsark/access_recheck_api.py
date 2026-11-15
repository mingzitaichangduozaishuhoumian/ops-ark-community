"""Append bounded, read-only verification to an original SSH outage report."""

import hashlib
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Response
from fastapi.params import Depends
from pydantic import AwareDatetime, Field

from opsark.access_recheck_store import (
    AccessCheckResult,
    AccessRecheck,
    ExternalObservation,
    access_outcome,
)
from opsark.baselines import diagnostic_scope_for
from opsark.business_readiness import BusinessReadiness, business_profile_digest
from opsark.config import HostConfig
from opsark.models import Report, StrictModel
from opsark.storage import ReportStore

_ROUTE = "/api/reports/{report_id}/access-rechecks"
_MISMATCH = "原失联报告或登记范围未能核实。"
_UNAVAILABLE = "失联复验记录暂时不可用。"
_REPORT_ID = r"^[A-Za-z0-9_-]{1,80}$"
ReportId = Annotated[str, Field(pattern=_REPORT_ID)]
ReceiptId = Annotated[str, Field(pattern=r"^ar-[0-9a-f]{32}$")]


class AccessRequest(StrictModel):
    external: ExternalObservation = "unavailable"


class AccessHistory(StrictModel):
    report_id: ReportId
    can_run: bool
    last_evidence_at: AwareDatetime | None
    rechecks: list[AccessRecheck]


def outage_report(report: Report) -> bool:
    return (
        report.source == "ssh"
        and report.scenario == "web_502"
        and report.status == "inconclusive"
        and len(report.evidence) == 1
        and report.evidence[0].source == "ssh"
        and report.evidence[0].check_id == "connection"
        and report.evidence[0].status in {"error", "timeout", "permission_denied"}
        and report.evidence[0].exit_code is None
    )


def access_profile(report: Report, host: HostConfig | None) -> str | None:
    if (
        host is None
        or not outage_report(report)
        or report.target is None
        or report.target.id != report.host_id
        or report.target.source != "ssh"
        or host.public.source != "ssh"
        or host.public.id != report.host_id
        or host.public.trusted_hosts_digest is None
        or not any(check.read_only_confirmed for check in host.business_checks)
        or report.scope_hash != diagnostic_scope_for(host.public)
        or report.scope_hash != diagnostic_scope_for(report.target)
    ):
        return None
    material = report.scope_hash + business_profile_digest(host)
    return hashlib.sha256(b"opsark-access-recheck-v1\0" + material.encode("ascii")).hexdigest()


def _last_evidence(store: ReportStore, original: Report) -> datetime | None:
    baseline_id = original.comparison.baseline_report_id
    if baseline_id is None or original.comparison.status == "scope_changed":
        return None
    baseline = store.get(baseline_id)
    if (
        baseline is None
        or baseline.source != "ssh"
        or baseline.scenario != original.scenario
        or baseline.host_id != original.host_id
        or baseline.scope_hash != original.scope_hash
        or baseline.target is None
        or diagnostic_scope_for(baseline.target) != baseline.scope_hash
    ):
        return None
    return max(
        (
            row.collected_at
            for row in baseline.evidence
            if row.source == "ssh"
            and row.status == "ok"
            and row.collected_at.utcoffset() is not None
            and row.collected_at < original.evidence[0].collected_at
        ),
        default=None,
    )


def _time(when: datetime) -> str:
    return when.astimezone(UTC).isoformat(timespec="seconds")


def _render(report: Report, last_evidence: datetime | None, receipt: AccessRecheck) -> str:
    statuses = {"accepted": "复验通过", "failed": "复验未通过", "pending": "待验收"}
    ssh = {"verified": "已通过登记身份认证", "unavailable": "未取得认证连接"}
    external = {"matched": "访问符合预期", "unreachable": "无法访问", "unavailable": "未取得"}
    outcomes = {
        "passed": "符合登记条件",
        "failed": "与登记条件不符",
        "inconclusive": "证据不足",
        "uncovered": "未覆盖",
    }
    return "\n".join(
        [
            "# OpsArk SSH 失联复验",
            "",
            f"- 原报告编号 `{receipt.report_id}`",
            f"- 复验编号 `{receipt.id}`",
            f"- 原连接失败时间 {_time(report.evidence[0].collected_at)}",
            f"- 最近可核实的历史证据 {_time(last_evidence) if last_evidence else '未取得'}",
            f"- 本次复验时间 {_time(receipt.finished_at)}",
            f"- 结果 **{statuses[receipt.status]}**",
            f"- SSH {ssh[receipt.management]}",
            f"- 机外观察（人工记录）{external[receipt.external]}",
            "",
            "## 登记业务检查",
            "",
            *(
                f"- 检查 {index} {outcomes[row.status]}"
                for index, row in enumerate(receipt.checks, 1)
            ),
            "",
            "人工记录与 SSH 内业务检查分别取证。复验只代表记录时点。"
            "待验收或未通过时，请核对管理连接与登记业务，再追加一条复验。",
            "",
        ]
    )


def register_access_recheck_routes(
    router: APIRouter,
    store: ReportStore,
    protected: Sequence[Depends],
    *,
    find_report: Callable[[str], Report],
    registered_hosts: Mapping[str, HostConfig],
    current_hosts: Callable[[], Mapping[str, HostConfig]],
    collect: Callable[[HostConfig], tuple[bool, BusinessReadiness]],
    collection_lock: Lock,
) -> None:
    def original(report_id: str) -> Report:
        report = find_report(report_id)
        if (
            not outage_report(report)
            or re.fullmatch(_REPORT_ID, report.id) is None
            or report.evidence[0].collected_at.utcoffset() is None
        ):
            raise HTTPException(409, _MISMATCH)
        return report

    def active(report: Report) -> tuple[HostConfig, str] | None:
        host = registered_hosts.get(report.host_id)
        profile = access_profile(report, host)
        if host is None or profile is None or store.access_profile(report.id) != profile:
            return None
        try:
            return (host, profile) if current_hosts().get(report.host_id) == host else None
        except (OSError, ValueError):
            return None

    @router.get(_ROUTE, dependencies=protected)
    def history(report_id: ReportId) -> AccessHistory:
        report = original(report_id)
        try:
            return AccessHistory(
                report_id=report.id,
                can_run=active(report) is not None,
                last_evidence_at=_last_evidence(store, report),
                rechecks=store.access_rechecks(report.id),
            )
        except (ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.post(_ROUTE, status_code=201, dependencies=protected)
    def recheck(report_id: ReportId, body: AccessRequest) -> AccessRecheck:
        report = original(report_id)
        if not collection_lock.acquire(blocking=False):
            raise HTTPException(409, "已有只读检查正在运行，请稍后重试。")
        try:
            binding = active(report)
            if binding is None:
                raise HTTPException(409, _MISMATCH)
            host, profile = binding
            management, result = collect(host)
            if (
                active(report) != binding
                or result.host_id != host.public.id
                or [row.id for row in result.checks] != [row.id for row in host.business_checks]
            ):
                raise HTTPException(409, _MISMATCH)
            checks = [AccessCheckResult(id=row.id, status=row.status) for row in result.checks]
            management_state = "verified" if management else "unavailable"
            receipt = AccessRecheck(
                id="ar-" + uuid4().hex,
                report_id=report.id,
                finished_at=datetime.now(UTC),
                management=management_state,
                external=body.external,
                checks=checks,
                status=access_outcome(management_state, body.external, checks),
            )
            store.save_access_recheck(receipt, profile=profile)
            return receipt
        except (ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None
        finally:
            collection_lock.release()

    @router.get(_ROUTE + "/{receipt_id}/handoff", dependencies=protected)
    def export(report_id: ReportId, receipt_id: ReceiptId) -> Response:
        report = original(report_id)
        try:
            receipt = store.get_access_recheck(report.id, receipt_id)
            if receipt is None:
                raise HTTPException(404, "原报告没有该复验记录。")
            markdown = _render(report, _last_evidence(store, report), receipt)
        except (ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None
        return Response(
            markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="opsark-access-recheck.md"'},
        )
