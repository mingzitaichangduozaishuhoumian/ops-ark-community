"""Protected, report-bound read-only verification for a container investigation."""

import hashlib
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from threading import Lock
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Response
from fastapi.params import Depends
from pydantic import Field

from opsark.baselines import diagnostic_scope_for
from opsark.business_readiness import BusinessReadiness, business_profile_digest
from opsark.config import HostConfig
from opsark.container_report_recheck_store import (
    CAPACITY,
    ContainerReportRecheck,
    Management,
    RecheckCapacity,
    RecheckId,
    ReportId,
    RequestId,
    container_report_scope,
    verdict,
)
from opsark.models import Report, StrictModel
from opsark.storage import ReportStore

_PATH = "/api/reports/{report_id}/container-rechecks"
_MISMATCH = "原容器调查或业务检查范围未能核实。"
_UNAVAILABLE = "容器业务复验暂时不可用。"
_FULL = "本报告的业务复验记录已达上限。"


class RecheckRequest(StrictModel):
    request_id: RequestId


class RecheckHistory(StrictModel):
    report_id: ReportId
    can_run: bool
    rechecks: list[ContainerReportRecheck] = Field(max_length=CAPACITY)


def container_recheck_profile(report: Report, host: HostConfig | None) -> str | None:
    scope = container_report_scope(report)
    if (
        scope is None
        or host is None
        or host.public.id != report.host_id
        or host.public.source != "ssh"
        or scope != diagnostic_scope_for(host.public)
        or not any(check.read_only_confirmed for check in host.business_checks)
    ):
        return None
    material = (scope + business_profile_digest(host)).encode("ascii")
    return hashlib.sha256(b"opsark-container-report-profile/v1\0" + material).hexdigest()


def _render(receipt: ContainerReportRecheck) -> str:
    results = {"failed": "复验未通过", "pending": "待验收", "passed": "复验通过"}
    checks = {
        "passed": "通过",
        "failed": "未通过",
        "inconclusive": "证据不足",
        "uncovered": "未覆盖",
    }
    management = "已取得认证连接" if receipt.management == "verified" else "未取得认证连接"
    return "\n".join(
        [
            "# OpsArk 容器调查业务复验",
            "",
            f"- 原报告编号 `{receipt.report_id}`",
            f"- 复验编号 `{receipt.id}`",
            f"- 复验时间 {receipt.finished_at.isoformat(timespec='seconds')}",
            f"- 结果 **{results[receipt.status]}**",
            f"- SSH {management}",
            "",
            "## 登记业务检查",
            "",
            *(f"- 检查 {number} {checks[check]}" for number, check in enumerate(receipt.checks, 1)),
            "",
            "结果仅覆盖复验时点的登记检查。故障原因、处置结果和持续观察需另行核实。",
            "",
        ]
    )


def register_container_report_recheck_routes(
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
            report.id != report_id
            or report.source != "ssh"
            or report.scenario != "container_restart"
        ):
            raise HTTPException(409, _MISMATCH)
        return report

    def active(report: Report) -> tuple[HostConfig, str] | None:
        host = registered_hosts.get(report.host_id)
        profile = container_recheck_profile(report, host)
        if host is None or profile is None or store.container_recheck_profile(report.id) != profile:
            return None
        try:
            return (host, profile) if current_hosts().get(report.host_id) == host else None
        except (OSError, ValueError):
            return None

    @router.get(_PATH, dependencies=protected)
    def history(report_id: ReportId) -> RecheckHistory:
        report = original(report_id)
        try:
            rechecks = list(store.container_rechecks(report.id).values())
            return RecheckHistory(
                report_id=report.id,
                can_run=len(rechecks) < CAPACITY and active(report) is not None,
                rechecks=rechecks,
            )
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.post(_PATH, status_code=201, dependencies=protected)
    def run(report_id: ReportId, body: RecheckRequest) -> ContainerReportRecheck:
        report = original(report_id)
        if not collection_lock.acquire(blocking=False):
            raise HTTPException(409, "已有只读检查正在运行，请稍后重试。")
        try:
            previous = store.container_rechecks(report.id)
            if body.request_id in previous:
                return previous[body.request_id]
            if len(previous) >= CAPACITY:
                raise HTTPException(409, _FULL)
            binding = active(report)
            if binding is None:
                raise HTTPException(409, _MISMATCH)
            host, profile = binding
            authenticated, result = collect(host)
            if (
                active(report) != binding
                or type(authenticated) is not bool
                or result.host_id != host.public.id
                or [item.id for item in result.checks]
                != [check.id for check in host.business_checks]
                or any(
                    not check.read_only_confirmed and item.status != "uncovered"
                    for check, item in zip(host.business_checks, result.checks, strict=True)
                )
            ):
                raise HTTPException(409, _MISMATCH)
            management: Management = "verified" if authenticated else "unavailable"
            checks = [item.status for item in result.checks]
            recorded = ContainerReportRecheck(
                id="rr-" + uuid4().hex,
                report_id=report.id,
                finished_at=datetime.now(UTC),
                management=management,
                checks=checks,
                status=verdict(management, checks),
            )
            return store.save_container_recheck(
                recorded, profile=profile, request_id=body.request_id
            )
        except RecheckCapacity:
            raise HTTPException(409, _FULL) from None
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None
        finally:
            collection_lock.release()

    @router.get(_PATH + "/{receipt_id}/handoff", dependencies=protected)
    def export(report_id: ReportId, receipt_id: RecheckId) -> Response:
        report = original(report_id)
        try:
            receipt = next(
                (
                    row
                    for row in store.container_rechecks(report.id).values()
                    if row.id == receipt_id
                ),
                None,
            )
            if receipt is None:
                raise HTTPException(404, "原报告没有该业务复验记录。")
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None
        return Response(
            _render(receipt),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="opsark-container-recheck.md"'},
        )
