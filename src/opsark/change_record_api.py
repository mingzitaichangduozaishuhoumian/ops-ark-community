"""Report-scoped operator statements and independently observed change intervals."""

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, HTTPException, Response
from fastapi.params import Depends
from pydantic import Field

from opsark.baselines import BaselineStore, diagnostic_scope_for
from opsark.change_record_store import (
    ChangeRecord,
    ChangeRecordConflict,
    ChangeRecordFutureInstant,
    ChangeRecordRequest,
    ChangeRecordScopeMismatch,
)
from opsark.compose_generation_store import (
    ChangeObservation,
    ComposeGenerationStore,
    change_observation,
)
from opsark.config import HostConfig
from opsark.models import Report, StrictModel
from opsark.storage import ReportStore

_ROUTE = "/api/reports/{report_id}/change-records"
_UNAVAILABLE = "变更记录暂时不可核实。"
_SCOPE = "原报告的登记范围与当前目标不一致。"
ReportId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
RecordId = Annotated[str, Field(pattern=r"^cr-[0-9a-f]{32}$")]

_KINDS = {
    "nginx_configuration": "Nginx 配置",
    "compose_configuration": "Compose 配置",
    "image_update": "镜像更新",
    "application_configuration": "应用配置",
    "service_restart": "服务重启",
    "unknown": "类型未知",
}


class ChangeHistory(StrictModel):
    report_id: ReportId
    can_record: bool
    records: list[ChangeRecord] = Field(max_length=20)
    observation: ChangeObservation


def _recordable(report: Report, registration: HostConfig | None) -> bool:
    target = report.target
    return (
        report.source == "ssh"
        and report.created_at.utcoffset() is not None
        and target is not None
        and target.source == "ssh"
        and target.id == report.host_id
        and target.trusted_hosts_digest is not None
        and registration is not None
        and registration.public.source == "ssh"
        and registration.public.id == report.host_id
        and registration.public.trusted_hosts_digest is not None
        and report.scope_hash
        == diagnostic_scope_for(target)
        == diagnostic_scope_for(registration.public)
    )


def _handoff(record: ChangeRecord) -> str:
    claim = record.claimed_at
    stated = claim.value or "未知"
    if claim.precision == "date":
        stated += "（日历日期）"
    recorded = record.recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    return "\n".join(
        [
            "# OpsArk 维护者变更陈述",
            "",
            f"- 原报告编号 `{record.report_id}`",
            f"- 记录编号 `{record.id}`",
            f"- 变更类型 {_KINDS[record.kind]}",
            f"- 声明时间 {stated}",
            f"- 控制端记录时间 {recorded}",
            "- 来源 维护者陈述，待核实",
            "",
            "实际执行时间、部署来源和操作者仍未知。声明时间不参与观测对比。",
            "",
        ]
    )


def register_change_record_routes(
    router: APIRouter,
    store: ReportStore,
    protected: Sequence[Depends],
    *,
    find_report: Callable[[str], Report],
    current_hosts: Callable[[], Mapping[str, HostConfig]],
    baselines: BaselineStore,
    generations: ComposeGenerationStore,
) -> None:
    def can_record(report: Report) -> bool:
        try:
            return _recordable(report, current_hosts().get(report.host_id))
        except (OSError, ValueError):
            return False

    @router.get(_ROUTE, dependencies=protected)
    def history(report_id: ReportId) -> ChangeHistory:
        report = find_report(report_id)
        try:
            records = store.change_records(report.id)
            return ChangeHistory(
                report_id=report.id,
                can_record=can_record(report),
                records=records,
                observation=change_observation(report, baselines, generations),
            )
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.post(_ROUTE, status_code=201, dependencies=protected)
    def add(report_id: ReportId, body: ChangeRecordRequest) -> ChangeRecord:
        report = find_report(report_id)
        if not can_record(report):
            raise HTTPException(409, _SCOPE)
        try:
            return store.save_change_record(report.id, host_scope=report.scope_hash, change=body)
        except KeyError:
            raise HTTPException(404, "报告不存在。") from None
        except ChangeRecordScopeMismatch:
            raise HTTPException(409, _SCOPE) from None
        except ChangeRecordFutureInstant:
            raise HTTPException(422, "声明的明确时刻不能在未来。") from None
        except ChangeRecordConflict as error:
            detail = (
                "本报告的变更记录已达上限。"
                if error.reason == "limit_reached"
                else "该请求编号已用于不同记录。"
            )
            raise HTTPException(409, detail) from None
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.get(_ROUTE + "/{record_id}/handoff", dependencies=protected)
    def export(report_id: ReportId, record_id: RecordId) -> Response:
        report = find_report(report_id)
        try:
            record = store.get_change_record(report.id, record_id)
            if record is None:
                raise HTTPException(404, "原报告没有该变更记录。")
            return Response(
                _handoff(record),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="opsark-change-record.md"'},
            )
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(503, _UNAVAILABLE) from None
