"""Safe, deterministic customer projection; no free-form investigation or log text."""

from typing import Literal

from pydantic import Field, model_validator

from opsark.defense_models import DefenseModel, Digest, Timestamp, utc

type RecheckVerdict = Literal["pending", "failed", "passed"]
type BusinessStatus = Literal["passed", "failed", "inconclusive", "uncovered"]
type RootState = Literal[
    "active",
    "expired",
    "revoked",
    "ready",
    "ready_expired",
    "unknown",
    "rejected",
    "not_found",
    "unavailable",
]
type CheckReason = Literal[
    "matched",
    "status_mismatch",
    "body_mismatch",
    "incomplete",
    "uncovered",
    "scope_changed",
    "time_unverified",
]
type HandoffReason = Literal[
    "not_run",
    "in_progress",
    "result_unknown",
    "root_unverified",
    "authority_unproven",
    "original_profile_missing",
    "scope_changed",
    "profile_changed",
    "time_unverified",
    "incomplete",
    "legacy_incomplete",
    "current_unknown",
    "current_unverified",
    "evidence_changed",
    "collector_unavailable",
    "business_failed",
    "interrupted",
    "newer_recheck",
]


class HandoffCheck(DefenseModel):
    number: int = Field(ge=1, le=3)
    status: BusinessStatus
    reason_code: CheckReason


class DefenseHandoffProjection(DefenseModel):
    """Only this closed shape is allowed into customer Markdown."""

    v: Literal[2] = 2
    task_reference_sha256: Digest | None = None
    original_authority_kind: Literal["human_approval", "preauthorization", "unproven"] = "unproven"
    original_authority_at: Timestamp | None = None
    execution_status: Literal["not_submitted", "submitted", "confirmed", "unproven"] = "unproven"
    execution_submitted_at: Timestamp | None = None
    execution_confirmed_at: Timestamp | None = None
    receipt_status: Literal["no_gap", "unconfirmed"] = "no_gap"
    receipt_unconfirmed_at: Timestamp | None = None
    reconciliation_status: Literal["not_needed", "reconciled", "pending"] = "pending"
    reconciled_at: Timestamp | None = None
    historical_verdict: RecheckVerdict = "pending"
    current_verdict: RecheckVerdict = "pending"
    business_verdict: RecheckVerdict = "pending"
    authority_kind: Literal["human_approval", "preauthorization", "unproven"] = "unproven"
    root_before: RootState = "unavailable"
    root_after: RootState = "unavailable"
    current_root: RootState = "unavailable"
    transition: Literal["unchanged", "ttl_elapsed", "changed", "unknown"] = "unknown"
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None
    root_observed_at: Timestamp | None = None
    current_root_observed_at: Timestamp | None = None
    checks: tuple[HandoffCheck, ...] = Field(default=(), max_length=3)
    reasons: tuple[HandoffReason, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def ordered_checks(self):
        if self.original_authority_kind != "unproven" and self.original_authority_at is None:
            raise ValueError("Original authority needs its Controller record time")
        if self.execution_status == "confirmed" and (
            self.execution_submitted_at is None
            or self.execution_confirmed_at is None
            or utc(self.execution_confirmed_at) < utc(self.execution_submitted_at)
        ):
            raise ValueError("Confirmed execution needs a closed original intent timeline")
        if self.receipt_status == "unconfirmed" and self.receipt_unconfirmed_at is None:
            raise ValueError("A receipt gap needs its own observation time")
        if self.reconciliation_status == "reconciled" and (
            self.receipt_status != "unconfirmed"
            or self.receipt_unconfirmed_at is None
            or self.reconciled_at is None
            or utc(self.reconciled_at) < utc(self.receipt_unconfirmed_at)
        ):
            raise ValueError("Reconciliation needs a later original task observation")
        if tuple(check.number for check in self.checks) != tuple(range(1, len(self.checks) + 1)):
            raise ValueError("Business check numbering must close")
        complete_checks = bool(self.checks) and all(
            check.status == "passed" for check in self.checks
        )
        known = {"active", "expired", "revoked"}
        if self.historical_verdict == "passed" and (
            not complete_checks
            or self.business_verdict != "passed"
            or self.authority_kind == "unproven"
            or self.root_before not in known
            or self.root_after not in known
            or self.started_at is None
            or self.finished_at is None
        ):
            raise ValueError("A passed recheck requires complete bound evidence")
        if self.current_verdict == "passed" and (
            self.historical_verdict != "passed"
            or self.current_root not in known
            or self.current_root_observed_at is None
            or self.execution_status != "confirmed"
            or self.original_authority_kind == "unproven"
            or self.reconciliation_status == "pending"
        ):
            raise ValueError("Current acceptance requires current Root evidence")
        return self


def merge_business(checks: tuple[HandoffCheck, ...]) -> RecheckVerdict:
    if any(check.status == "failed" for check in checks):
        return "failed"
    if checks and all(check.status == "passed" for check in checks):
        return "passed"
    return "pending"


def merge_verdict(checks: tuple[HandoffCheck, ...], *, bindings_complete: bool) -> RecheckVerdict:
    business = merge_business(checks)
    if business == "failed":
        return "failed"
    return "passed" if business == "passed" and bindings_complete else "pending"


_VERDICT = {"pending": "待验收", "failed": "复验未通过", "passed": "登记业务复验通过"}
_CHECK = {
    "passed": "通过",
    "failed": "未通过",
    "inconclusive": "未取得完整证据",
    "uncovered": "未覆盖",
}
_ROOT = {
    "active": "已确认生效（仅代表查询时刻）",
    "expired": "已到期，不代表仍在阻断",
    "revoked": "已确认撤销",
    "ready": "仅准备完成，执行未确认",
    "ready_expired": "准备期限已结束，执行未确认",
    "unknown": "原任务结果未知",
    "rejected": "原请求被拒绝",
    "not_found": "原任务尚未核实",
    "unavailable": "未取得可信查询",
}
_AUTHORITY = {
    "human_approval": "控制端已记录原任务的精确确认声明",
    "preauthorization": "原任务的预授权账本与远端回执已核实",
    "unproven": "原任务授权依据尚未核实",
}


def defense_handoff_markdown(projection: DefenseHandoffProjection) -> str:
    projection = DefenseHandoffProjection.model_validate_json(projection.model_dump_json())
    lines = [
        "# OpsArk 防护任务交接摘要",
        "",
        f"**当前验收：{_VERDICT[projection.current_verdict]}。**",
        "",
        f"所选历史复验：{_VERDICT[projection.historical_verdict]}。",
        f"业务检查：{_VERDICT[projection.business_verdict]}。",
        "",
        f"- 所选复验记录中的授权依据：{_AUTHORITY[projection.authority_kind]}。",
        f"- 复验前原任务：{_ROOT[projection.root_before]}。",
        f"- 复验后原任务：{_ROOT[projection.root_after]}。",
        f"- 当前本地对账：{_ROOT[projection.current_root]}。",
    ]
    if projection.task_reference_sha256 is not None:
        lines.append(f"- 服务端任务引用摘要：{projection.task_reference_sha256}。")
    execution = {
        "not_submitted": "未核实原执行提交",
        "submitted": "原执行提交意图已记录，生效尚未确认",
        "confirmed": "原执行已由同一清单的可信生效回执确认",
        "unproven": "原执行证据尚未闭合",
    }
    reconciliation = {
        "not_needed": "未记录待对账的回执缺口",
        "reconciled": "其后已查询原任务并完成状态对账",
        "pending": "原任务仍待查询对账",
    }
    lines.extend(
        [
            "",
            "## 原执行与原任务对账",
            "",
            f"- {_AUTHORITY[projection.original_authority_kind]}。",
            f"- {execution[projection.execution_status]}。",
        ]
    )
    if projection.receipt_status == "unconfirmed":
        lines.append("- 曾有原任务回执未确认；现有记录不能据此断定发生网络断线。")
    lines.append(f"- {reconciliation[projection.reconciliation_status]}。")
    for label, value in (
        ("原授权依据记录", projection.original_authority_at),
        ("原执行提交意图记录", projection.execution_submitted_at),
        ("原执行可信生效回执", projection.execution_confirmed_at),
        ("最近一次回执未确认", projection.receipt_unconfirmed_at),
        ("后续原任务查询对账", projection.reconciled_at),
    ):
        if value is not None:
            lines.append(f"- {label}（控制端 UTC）：{value}。")
    if projection.transition == "ttl_elapsed":
        lines.append("- 本轮严格查询确认防护自然到期；到期本身不证明业务通过或失败。")
    if "interrupted" in projection.reasons:
        lines.append("- 本次未完成复验已显式中断；原结果仍待验收，未补造业务检查结果。")
    if "legacy_incomplete" in projection.reasons:
        lines.append("- 旧版工程复验记录缺少完整业务证据，仅供历史查阅，不能作为业务验收通过。")
    if projection.started_at is not None:
        lines.append(f"- 复验开始（UTC）：{projection.started_at}。")
    if projection.finished_at is not None:
        lines.append(f"- 复验结束（UTC）：{projection.finished_at}。")
    if projection.root_observed_at is not None:
        lines.append(f"- 原任务查询（UTC）：{projection.root_observed_at}。")
    passed = sum(check.status == "passed" for check in projection.checks)
    lines.extend(["", f"登记业务检查符合 {passed} / {len(projection.checks)} 项。"])
    if projection.checks:
        lines.extend(["", "| 检查 | 结果 |", "| --- | --- |"])
        for check in projection.checks:
            lines.append(f"| 检查 {check.number} | {_CHECK[check.status]} |")
    if projection.reasons:
        lines.extend(["", "存在未完成或未能核实的证据，请在控制台读取原记录继续核对。"])
    lines.extend(
        [
            "",
            "本摘要仅覆盖所选任务和登记的即时只读检查。",
            "业务检查结果与防护元素状态分开记录；完整业务恢复及持续观察仍需另行验收。",
        ]
    )
    return "\n".join(lines) + "\n"
