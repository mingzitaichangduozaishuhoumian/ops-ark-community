"""Protected customer action export and explicitly requested, bodyless rechecks."""

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from threading import Lock
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from fastapi.responses import Response
from pydantic import AwareDatetime

from opsark.action_handoff import action_handoff_markdown
from opsark.action_handoff_projection import ActionHandoffProjection, ActionHandoffRecheckSummary
from opsark.action_handoff_recheck_store import (
    ActionHandoffRecheckStore,
    ActionKind,
    CheckState,
    PlanId,
    ReportId,
    RunId,
)
from opsark.business_readiness import BusinessReadiness
from opsark.config import HostConfig
from opsark.container_restarts import ContainerRestartService
from opsark.models import Report, StrictModel
from opsark.nginx_actions import NginxActionService

_ACTIONS = "/api/reports/{report_id}/handoff-actions"
_ROOT = _ACTIONS + "/{kind}/{plan_id}"
_MISMATCH = "所选处置或复验记录与本次调查的绑定未能核实。"
_UNAVAILABLE = "处置交接记录暂时无法核实。"


class ActionRechecks(StrictModel):
    can_run: bool
    rechecks: list[ActionHandoffRecheckSummary]


class ActionOption(StrictModel):
    kind: ActionKind
    plan_id: PlanId
    action: Literal["apply", "restore", "restart"]
    approved_at: AwareDatetime


class ActionOptions(StrictModel):
    actions: list[ActionOption]


def _checks(
    result: BusinessReadiness, host: HostConfig
) -> tuple[CheckState, CheckState, CheckState]:
    if (
        not 1 <= len(host.business_checks) <= 3
        or result.host_id != host.public.id
        or [row.id for row in result.checks] != [check.id for check in host.business_checks]
    ):
        raise ValueError("Unexpected business check identity")
    statuses: list[CheckState] = ["uncovered", "uncovered", "uncovered"]
    for index, row in enumerate(result.checks):
        if row.status in ("passed", "failed"):
            statuses[index] = row.status
    return statuses[0], statuses[1], statuses[2]


def register_action_handoff_routes(
    router: APIRouter,
    projection: ActionHandoffProjection,
    rechecks: ActionHandoffRecheckStore,
    protected: Sequence[Depends],
    *,
    nginx: NginxActionService,
    container: ContainerRestartService,
    find_report: Callable[[str], Report],
    registered_hosts: Mapping[str, HostConfig],
    current_hosts: Callable[[], Mapping[str, HostConfig]],
    collect: Callable[[HostConfig], BusinessReadiness],
    collection_lock: Lock,
) -> None:
    def active_profile(host_id: str) -> HostConfig | None:
        startup = registered_hosts.get(host_id)
        if startup is None:
            return None
        try:
            latest = current_hosts().get(host_id)
        except (ValueError, OSError):
            # Saved history can still be read when the deployed inventory is unavailable.
            return None
        return startup if latest == startup else None

    @router.get(_ACTIONS, dependencies=protected)
    def options(report_id: ReportId) -> ActionOptions:
        report = find_report(report_id)
        try:
            rows = []
            services: tuple[
                tuple[ActionKind, NginxActionService | ContainerRestartService], ...
            ] = (
                ("nginx", nginx),
                ("container_restart", container),
            )
            for kind, service in services:
                for plan_id in service.handoff_plan_ids(report.id):
                    timeline = projection.timeline(report.id, kind, plan_id)
                    if timeline is not None:
                        rows.append(
                            ActionOption(
                                kind=kind,
                                plan_id=plan_id,
                                approved_at=timeline.approved_at,
                                action="apply"
                                if timeline.kind == "nginx_apply"
                                else "restore"
                                if timeline.kind == "nginx_restore"
                                else "restart",
                            )
                        )
            rows.sort(key=lambda row: (row.approved_at, row.plan_id), reverse=True)
            return ActionOptions(actions=rows[:20])
        except ValueError:
            raise HTTPException(409, _MISMATCH) from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.get(_ROOT, dependencies=protected)
    def export(
        report_id: ReportId, kind: ActionKind, plan_id: PlanId, recheck_id: RunId | None = None
    ) -> Response:
        report = find_report(report_id)
        try:
            timeline = projection.timeline(
                report.id,
                kind,
                plan_id,
                profile=active_profile(report.host_id),
                recheck_id=recheck_id,
            )
            if timeline is None:
                raise HTTPException(404, "找不到原处置交接记录。")
            rendered = action_handoff_markdown(timeline)
        except ValueError:
            raise HTTPException(409, _MISMATCH) from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None
        return Response(
            rendered,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="opsark-action-handoff.md"'},
        )

    @router.get(_ROOT + "/rechecks", dependencies=protected)
    def history(report_id: ReportId, kind: ActionKind, plan_id: PlanId) -> ActionRechecks:
        report = find_report(report_id)
        profile = active_profile(report.host_id)
        try:
            rows = projection.rechecks(report.id, kind, plan_id, profile=profile)
            can_run = False
            if profile is not None:
                try:
                    projection.binding(report.id, kind, plan_id, profile)
                    can_run = True
                except ValueError:
                    pass
            return ActionRechecks(can_run=can_run, rechecks=rows)
        except ValueError:
            raise HTTPException(409, _MISMATCH) from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None

    @router.post(_ROOT + "/rechecks", dependencies=protected, status_code=201)
    def recheck(
        report_id: ReportId, kind: ActionKind, plan_id: PlanId
    ) -> ActionHandoffRecheckSummary:
        if not collection_lock.acquire(blocking=False):
            raise HTTPException(409, "已有只读检查正在运行，请稍后重试。")
        try:
            report = find_report(report_id)
            profile = active_profile(report.host_id)
            if profile is None:
                raise ValueError("Host is no longer registered")
            binding = projection.binding(report.id, kind, plan_id, profile)
            intent = rechecks.start(binding)
            checks = _checks(collect(profile), profile)
            latest = active_profile(report.host_id)
            if (
                latest != profile
                or projection.binding(report.id, kind, plan_id, profile) != binding
            ):
                raise ValueError("Action or business profile changed during recheck")
            finished = rechecks.finish(binding, intent.id, checks=checks)
            # The two ledgers have independent SQLite transactions. Recheck the current
            # epoch at read time before presenting the just-recorded result as current.
            selected = projection.timeline(
                report.id, kind, plan_id, profile=profile, recheck_id=intent.id
            )
            if selected is None or selected.business is None:
                raise ValueError("Saved business recheck is unconfirmed")
            return ActionHandoffRecheckSummary(
                id=intent.id,
                selection=selected.business.selection,
                verdict=finished.verdict,
                started_at=intent.started_at,
                finished_at=selected.business.finished_at,
            )
        except ValueError:
            raise HTTPException(409, _MISMATCH) from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, _UNAVAILABLE) from None
        finally:
            collection_lock.release()
