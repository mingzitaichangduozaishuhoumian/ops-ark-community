"""Render an already projected structured action timeline for a customer."""

from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from opsark.models import StrictModel

ActionKind = Literal["nginx_apply", "nginx_restore", "container_restart"]
OperationStatus = Literal["verified", "unknown", "not_started", "refused"]
ReconciliationStatus = Literal["verified", "disk_published_live_previous", "unchanged_from_preview"]
BusinessStatus = Literal["pending", "failed", "passed"]
_CheckCount = Annotated[int, Field(strict=True, ge=0, le=3)]


class BusinessSnapshot(StrictModel, strict=True, frozen=True):
    """Typed outcomes only. The caller must verify the original action and check profile."""

    selection: Literal["current", "historical"]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    configured_checks: Annotated[int, Field(strict=True, ge=1, le=3)]
    passed_checks: _CheckCount
    failed_checks: _CheckCount

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if (
            self.finished_at < self.started_at
            or self.passed_checks + self.failed_checks > self.configured_checks
        ):
            raise ValueError("业务复验时间或计数不一致。")
        return self

    @property
    def status(self) -> BusinessStatus:
        if self.failed_checks:
            return "failed"
        if self.passed_checks == self.configured_checks:
            return "passed"
        return "pending"


class ActionTimeline(StrictModel, strict=True, frozen=True):
    """Render the supplied execution epoch, including its matching business snapshot."""

    kind: ActionKind
    investigated_at: AwareDatetime
    approved_at: AwareDatetime
    receipt_observed_at: AwareDatetime | None = None
    operation_status: OperationStatus
    reconciliation_status: ReconciliationStatus | None = None
    business: BusinessSnapshot | None = None

    @property
    def operation_verified(self) -> bool:
        return self.operation_status == "verified" or self.reconciliation_status == "verified"

    @model_validator(mode="after")
    def validate_timeline(self) -> Self:
        observed = self.receipt_observed_at
        if (
            self.approved_at < self.investigated_at
            or (observed is not None and observed < self.approved_at)
            or (self.operation_status != "unknown" and observed is None)
            or (
                self.reconciliation_status is not None
                and (self.operation_status != "unknown" or observed is None)
            )
            or (
                self.reconciliation_status == "disk_published_live_previous"
                and self.kind != "nginx_apply"
            )
            or (
                self.reconciliation_status == "unchanged_from_preview"
                and self.kind == "container_restart"
            )
        ):
            raise ValueError("处置回执状态或时间不一致。")
        if self.business is not None and (
            not self.operation_verified or observed is None or self.business.started_at <= observed
        ):
            raise ValueError("业务复验须在原处置核实后开始。")
        return self


_ACTIONS = {
    "nginx_apply": "Nginx 配置变更",
    "nginx_restore": "Nginx 配置回退",
    "container_restart": "容器重启",
}
_OPERATIONS = {
    "verified": "原动作已核实",
    "unknown": "原动作结果未知，待对账",
    "not_started": "已核实原动作未开始",
    "refused": "原动作被拒绝",
}
_RECONCILIATIONS = {
    "verified": "已对账，原动作已核实",
    "disk_published_live_previous": "已核实配置写入磁盘，服务仍使用原配置，原动作待核实",
    "unchanged_from_preview": "已核实仍符合变更前状态，原动作结果仍未知",
}
_BUSINESS = {"pending": "待验收", "failed": "复验未通过", "passed": "登记业务复验通过"}


def _time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def action_handoff_markdown(timeline: ActionTimeline) -> str:
    """Render a standalone Markdown document using fixed labels and checked counts."""
    # Revalidate even if a caller constructed or copied the model without validation.
    if type(timeline) is not ActionTimeline:
        raise TypeError("需要已归类的处置交接记录。")
    timeline = ActionTimeline.model_validate(timeline.model_dump())
    kind = _ACTIONS[timeline.kind]
    operation = (
        _RECONCILIATIONS[timeline.reconciliation_status]
        if timeline.reconciliation_status is not None
        else _OPERATIONS[timeline.operation_status]
    )
    lines = [
        "# OpsArk 客户交接摘要",
        "",
        "## 处置时间线",
        "",
        "| 时间（UTC） | 记录 |",
        "| --- | --- |",
        f"| {_time(timeline.investigated_at)} | 原调查已记录 |",
        f"| {_time(timeline.approved_at)} | 已人工批准{kind} |",
    ]
    if timeline.receipt_observed_at is not None:
        lines.append(f"| {_time(timeline.receipt_observed_at)} | 已读取原动作回执 |")
    lines.extend(["", f"**{operation}。**", "", "## 业务复验", ""])
    business = timeline.business
    if business is None:
        lines.append("**待验收。** 尚无所选业务复验记录。")
    else:
        if business.selection == "historical":
            lines.append("以下为所选历史复验。当前业务状态需另行核对。")
            lines.append("")
        lines.extend(
            [
                f"**{_BUSINESS[business.status]}。**",
                f"复验时间（UTC）为 {_time(business.finished_at)}。",
                f"{business.passed_checks} / {business.configured_checks} 项登记检查符合条件。",
            ]
        )
    lines.extend(["", "业务验收范围限于本次登记检查。持续观察和未覆盖的业务环节需另行核对。", ""])
    return "\n".join(lines)
