"""Mode and authorization decisions; this module never executes a repair."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

from opsark.models import StrictModel

PackageName = Annotated[
    str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]{0,79}(?::[a-z0-9-]{1,20})?$", strict=True)
]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", strict=True)]
Version = Annotated[str, Field(pattern=r"^[0-9][0-9A-Za-z.+:~_-]{0,159}$", strict=True)]
HostIdentifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$", strict=True)]
NativePackageName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]{0,79}$", strict=True)]
AdvisoryIdentifier = Annotated[str, Field(pattern=r"^USN-[0-9]{1,8}-[0-9]{1,4}$", strict=True)]


class MaintenanceWindow(StrictModel):
    """UTC intervals; a cross-midnight interval belongs to its starting weekday."""

    weekdays: tuple[Annotated[int, Field(ge=0, le=6, strict=True)], ...] = Field(
        min_length=1, max_length=7
    )
    start_minute: int = Field(ge=0, le=1439, strict=True)
    end_minute: int = Field(ge=1, le=1440, strict=True)

    @model_validator(mode="after")
    def validate_interval(self):
        if len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError("维护窗口的星期不能重复。")
        if self.start_minute == self.end_minute:
            raise ValueError("维护窗口不能为空；全天必须明确使用 0 至 1440。")
        self.weekdays = tuple(sorted(self.weekdays))
        return self


class AutomaticGrant(StrictModel):
    """Deployment-owned pre-authorization; selecting a mode never creates one."""

    schema_version: int = Field(default=1, ge=1, le=1, strict=True)
    enabled: bool = Field(default=False, strict=True)
    grant_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", strict=True)]
    issued_at: datetime
    expires_at: datetime
    host_ids: tuple[HostIdentifier, ...] = Field(min_length=1, max_length=10)
    allowed_packages: tuple[NativePackageName, ...] = Field(min_length=1, max_length=20)
    allowed_advisories: tuple[AdvisoryIdentifier, ...] = Field(min_length=1, max_length=5)
    target_policy_digests: dict[HostIdentifier, Digest] = Field(min_length=1, max_length=10)
    maintenance_windows: tuple[MaintenanceWindow, ...] = Field(min_length=1, max_length=7)
    max_jobs_per_day: int = Field(default=1, ge=1, le=5, strict=True)
    max_total_jobs: int = Field(default=1, ge=1, le=5, strict=True)
    allowed_risk_levels: tuple[Literal["low", "medium"], ...] = Field(
        default=("low",), min_length=1, max_length=2
    )
    allow_service_restart: bool = Field(default=False, strict=True)
    grant_digest: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("自动预授权的时间必须包含时区。")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_and_bind(self):
        for values in (
            self.host_ids,
            self.allowed_packages,
            self.allowed_advisories,
            self.allowed_risk_levels,
        ):
            if len(values) != len(set(values)):
                raise ValueError("自动预授权范围不能重复。")
        if set(self.host_ids) != set(self.target_policy_digests):
            raise ValueError("每个自动目标必须且只能绑定一份远端策略摘要。")
        if not timedelta(0) < self.expires_at - self.issued_at <= timedelta(hours=24):
            raise ValueError("自动预授权有效期必须大于零且不超过二十四小时。")
        self.host_ids = tuple(sorted(self.host_ids))
        self.allowed_packages = tuple(sorted(self.allowed_packages))
        self.allowed_advisories = tuple(sorted(self.allowed_advisories))
        self.allowed_risk_levels = tuple(sorted(self.allowed_risk_levels))
        value = self.model_dump(mode="json", exclude={"grant_digest"})
        expected = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.grant_digest and self.grant_digest != expected:
            raise ValueError("自动预授权摘要与内容不一致。")
        self.grant_digest = expected
        return self


def automatic_window_open(grant: AutomaticGrant, now: datetime | None = None) -> bool:
    """Check grant lifetime and UTC windows; quotas and scope need the full evaluator."""
    grant = AutomaticGrant.model_validate(grant.model_dump())
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("自动决策时间必须包含时区。")
    instant = instant.astimezone(UTC)
    if not grant.enabled or not grant.issued_at <= instant < grant.expires_at:
        return False
    minute = instant.hour * 60 + instant.minute
    weekday = instant.weekday()
    for window in grant.maintenance_windows:
        if window.start_minute < window.end_minute:
            if weekday in window.weekdays and window.start_minute <= minute < window.end_minute:
                return True
        elif (
            weekday in window.weekdays
            and minute >= window.start_minute
            or (weekday - 1) % 7 in window.weekdays
            and minute < window.end_minute
        ):
            return True
    return False


class Mode(StrEnum):
    manual = "manual"
    assisted = "assisted"
    automatic = "automatic"


MODE_CATALOG = [
    {"id": "manual", "name": "手动模式", "description": "扫描、提供证据和建议，不执行修复。"},
    {"id": "assisted", "name": "半自动模式", "description": "预览具体修复方案，确认后执行并验证。"},
    {
        "id": "automatic",
        "name": "全自动模式",
        "description": "在预授权目标和动作范围内自行扫描、修复、验证和通知；条件不明时暂停该动作。",
    },
]


class AutomaticAIPolicy(StrictModel):
    """Independent model-call consent and budget; never grants Root execution rights."""

    enabled: bool = Field(default=False, strict=True)
    provider_fingerprint: Digest | None = None
    max_analyses_per_day: int = Field(default=1, ge=1, le=5, strict=True)
    max_total_analyses: int = Field(default=1, ge=1, le=5, strict=True)

    @model_validator(mode="after")
    def bind_provider(self):
        if self.enabled and self.provider_fingerprint is None:
            raise ValueError("自动 AI 分析必须明确绑定提供方配置摘要。")
        return self


ServiceUnit = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.service$", strict=True)
]


class ServiceActivationPolicy(StrictModel):
    enabled: bool = Field(default=False, strict=True)
    host_ids: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")], ...] = (
        Field(default=(), max_length=10)
    )
    allowed_units: tuple[ServiceUnit, ...] = Field(default=(), max_length=10)
    allowed_packages: tuple[PackageName, ...] = Field(default=(), max_length=20)
    allow_critical_units: tuple[Literal["dbus.service"], ...] = Field(default=(), max_length=1)
    max_services_per_activation: int = Field(default=1, ge=1, le=1, strict=True)

    @model_validator(mode="after")
    def bounded_scope(self):
        for values in (self.host_ids, self.allowed_units, self.allowed_packages):
            if len(values) != len(set(values)):
                raise ValueError("服务激活范围不能重复。")
        if not set(self.allow_critical_units) <= set(self.allowed_units):
            raise ValueError("关键服务例外必须同时在明确服务范围内。")
        if self.enabled and not (self.host_ids and self.allowed_units and self.allowed_packages):
            raise ValueError("启用服务激活必须明确目标、服务和原补丁包范围。")
        forbidden = {"ssh.service", "sshd.service", "docker.service", "containerd.service"}
        if any(
            unit.lower() in forbidden or unit.lower().startswith(("systemd", "network"))
            for unit in self.allowed_units
        ):
            raise ValueError("此版本不支持激活管理连接、网络或容器基础服务。")
        if "dbus.service" in self.allowed_units and "dbus.service" not in self.allow_critical_units:
            raise ValueError("D-Bus 激活需要独立的受控实验关键服务例外。")
        return self


class ControlPolicy(StrictModel):
    enabled: bool = Field(default=False, strict=True)
    host_ids: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")], ...] = (
        Field(default=(), max_length=10)
    )
    allowed_actions: tuple[Literal["os_security_upgrade"], ...] = ()
    allowed_packages: tuple[PackageName, ...] = Field(default=(), max_length=20)
    max_packages_per_job: int = Field(default=5, ge=1, le=5, strict=True)
    allow_reboot: bool = Field(default=False, strict=True)
    allow_service_restart: bool = Field(default=False, strict=True)
    automatic: AutomaticGrant | None = None
    automatic_ai: AutomaticAIPolicy | None = None
    service_activation: ServiceActivationPolicy | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_projection(self, handler):
        value = handler(self)
        if self.service_activation is None:
            value.pop("service_activation", None)
        return value

    @model_validator(mode="after")
    def unique_scope(self):
        for values in (self.host_ids, self.allowed_actions, self.allowed_packages):
            if len(set(values)) != len(values):
                raise ValueError("策略范围不能重复。")
        if self.automatic is not None and self.automatic.enabled:
            if not set(self.automatic.host_ids) <= set(self.host_ids) or not set(
                self.automatic.allowed_packages
            ) <= set(self.allowed_packages):
                raise ValueError("自动预授权不能扩大已有目标或包范围。")
            if "os_security_upgrade" not in self.allowed_actions:
                raise ValueError("自动预授权需要已登记的软件安全升级动作。")
        if (
            self.automatic_ai is not None
            and self.automatic_ai.enabled
            and (not self.enabled or self.automatic is None or not self.automatic.enabled)
        ):
            raise ValueError("自动 AI 分析需要已启用的上层策略和独立自动执行预授权。")
        if (
            self.service_activation is not None
            and self.service_activation.enabled
            and (
                not self.enabled
                or not self.allow_service_restart
                or not set(self.service_activation.host_ids) <= set(self.host_ids)
                or not set(self.service_activation.allowed_packages) <= set(self.allowed_packages)
                or "os_security_upgrade" not in self.allowed_actions
            )
        ):
            raise ValueError("服务激活不能扩大已有目标、补丁包或服务重启权限。")
        return self


class PackageChange(StrictModel):
    name: PackageName
    current_version: Version
    fixed_version: Version | None = None
    candidate_version: Version | None = None
    vendor_security_origin_verified: bool = Field(default=False, strict=True)
    candidate_contains_fixed_verified: bool = Field(default=False, strict=True)
    candidate_is_upgrade_verified: bool = Field(default=False, strict=True)
    current_is_affected_verified: bool = Field(default=False, strict=True)


class PatchPlan(StrictModel):
    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    action: Literal["os_security_upgrade"] = "os_security_upgrade"
    package_changes: list[PackageChange] = Field(min_length=1, max_length=5)
    state_digest: Digest
    expires_at: datetime
    requires_reboot: bool = Field(default=False, strict=True)
    requires_service_restart: bool = Field(default=False, strict=True)
    evidence_complete: bool = Field(default=False, strict=True)
    transaction_complete_verified: bool = Field(default=False, strict=True)
    restart_impact_verified: bool = Field(default=False, strict=True)
    risk_level: Literal["low", "medium", "high", "unknown"] = "unknown"
    plan_digest: str = ""

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("修复方案必须有带时区的过期时间。")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind(self):
        names = [p.name for p in self.package_changes]
        if len(names) != len(set(names)):
            raise ValueError("修复包不能重复。")
        value = self.model_dump(mode="json", exclude={"plan_digest"})
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("方案摘要与内容不一致。")
        self.plan_digest = digest
        return self


class PlanApproval(StrictModel):
    host_id: str
    plan_digest: Digest
    state_digest: Digest
    approved_at: datetime
    expires_at: datetime

    @field_validator("approved_at", "expires_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("批准时间必须包含时区。")
        return value.astimezone(UTC)


class Decision(StrictModel):
    action: Literal["advice_only", "await_approval", "authorized", "blocked"]
    reasons: list[str]
    plan_digest: str
    mode: Mode
    executable: bool = False


def evaluate_plan(
    mode: Mode | str,
    policy: ControlPolicy,
    plan: PatchPlan,
    current_state_digest: str,
    approval: PlanApproval | None = None,
    now: datetime | None = None,
) -> Decision:
    mode = Mode(mode)
    policy = ControlPolicy.model_validate(policy.model_dump())
    plan = PatchPlan.model_validate(plan.model_dump())
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("决策时间必须包含时区。")

    def result(action, reasons):
        return Decision(
            action=action,
            reasons=reasons,
            plan_digest=plan.plan_digest,
            mode=mode,
            executable=action == "authorized",
        )

    if mode == Mode.manual:
        return result("advice_only", ["手动模式仅提供扫描结果和修复建议。"])
    blocked = []
    if not policy.enabled:
        blocked.append("修复执行策略尚未启用。")
    if plan.host_id not in policy.host_ids or plan.action not in policy.allowed_actions:
        blocked.append("目标或动作不在授权范围。")
    if len(plan.package_changes) > policy.max_packages_per_job or any(
        p.name not in policy.allowed_packages for p in plan.package_changes
    ):
        blocked.append("软件包集合超出授权范围。")
    if instant >= plan.expires_at:
        blocked.append("方案已过期。")
    if plan.expires_at > instant + timedelta(minutes=30):
        blocked.append("方案有效期超出三十分钟。")
    if current_state_digest != plan.state_digest:
        blocked.append("服务器状态已变化，需要重新规划。")
    if not plan.evidence_complete:
        blocked.append("缺少完整的修复依据。")
    if not plan.transaction_complete_verified:
        blocked.append("尚未核实完整依赖和软件包变化集合。")
    if not plan.restart_impact_verified:
        blocked.append("尚未核实服务和系统重启影响。")
    for p in plan.package_changes:
        if (
            not p.fixed_version
            or not p.candidate_version
            or not p.vendor_security_origin_verified
            or not p.candidate_contains_fixed_verified
            or not p.candidate_is_upgrade_verified
            or not p.current_is_affected_verified
        ):
            blocked.append("缺少供应商已修复版本、可信安全仓库或版本比较证据。")
        elif p.current_version == p.candidate_version:
            blocked.append("没有需要执行的软件包变化。")
        elif p.current_version == p.fixed_version:
            blocked.append("当前版本已包含该修复，需要重新核实受影响状态。")
    if plan.requires_reboot and not policy.allow_reboot:
        blocked.append("当前策略没有授权重启服务器。")
    if plan.requires_service_restart and not policy.allow_service_restart:
        blocked.append("当前策略没有授权服务重启。")
    if blocked:
        return result("blocked", list(dict.fromkeys(blocked)))
    if mode == Mode.automatic:
        return result("blocked", ["自动模式必须经过完整的预授权、窗口和配额评估。"])
    if plan.risk_level == "unknown":
        return result("await_approval", ["影响范围尚未确定，先补齐证据并重新规划。"])
    if approval is None:
        return result("await_approval", ["当前方案需要一次明确批准。"])
    approval = PlanApproval.model_validate(approval.model_dump())
    if (
        approval.host_id != plan.host_id
        or approval.plan_digest != plan.plan_digest
        or approval.state_digest != current_state_digest
        or not approval.approved_at <= instant < approval.expires_at
        or approval.expires_at > plan.expires_at
        or approval.expires_at - approval.approved_at > timedelta(minutes=10)
    ):
        return result("blocked", ["批准与当前方案、状态或有效期不匹配。"])
    return result("authorized", ["当前具体方案已获批准，可执行并验证。"])


def evaluate_automatic_plan(
    policy: ControlPolicy,
    plan: PatchPlan,
    *,
    advisory_id: str,
    current_policy_digest: str,
    jobs_today: int,
    total_jobs: int,
    latch_paused: bool,
    now: datetime | None = None,
) -> Decision:
    """Check explicit grants; live state and actual APT transactions remain root-authoritative.

    The plan digest here binds this domain projection, not the remote full-plan digest.
    Usage counters include reserved intents, failures and unknown submissions. Daily usage
    is host-wide across grants, total usage is by grant_id, and a pause is host-wide.
    """
    policy = ControlPolicy.model_validate(policy.model_dump())
    plan = PatchPlan.model_validate(plan.model_dump())
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("自动决策时间必须包含时区。")
    instant = instant.astimezone(UTC)
    reasons = []
    # Reuse all deterministic plan prerequisites, without inventing a human approval.
    base = evaluate_plan(Mode.assisted, policy, plan, plan.state_digest, now=instant)
    if base.action == "blocked":
        reasons.extend(base.reasons)
    grant = policy.automatic
    if grant is None or not grant.enabled:
        reasons.append("没有启用明确的自动预授权。")
    if len(plan.package_changes) != 1:
        reasons.append("自动修复只允许一个已核实的软件包变化。")
    if plan.requires_reboot:
        reasons.append("自动预授权不允许重启主机。")
    if plan.risk_level not in {"low", "medium"}:
        reasons.append("高风险或未知影响不能自动执行。")
    if type(latch_paused) is not bool or latch_paused:
        reasons.append("自动处理已暂停或暂停状态未核实。")
    counters_known = all(
        type(value) is int and 0 <= value <= 2**63 - 1 for value in (jobs_today, total_jobs)
    )
    if not counters_known:
        reasons.append("缺少可信的已用任务配额，不能按零用量放行。")
    if grant is not None:
        if not automatic_window_open(grant, instant):
            reasons.append("预授权未生效、已到期或当前不在 UTC 维护窗口。")
        if plan.host_id not in grant.host_ids or any(
            p.name not in grant.allowed_packages for p in plan.package_changes
        ):
            reasons.append("目标或软件包不在自动预授权范围。")
        if not isinstance(advisory_id, str) or advisory_id not in grant.allowed_advisories:
            reasons.append("供应商公告不在自动预授权范围。")
        if (
            not isinstance(current_policy_digest, str)
            or not re_digest(current_policy_digest)
            or grant.target_policy_digests.get(plan.host_id) != current_policy_digest
        ):
            reasons.append("远端策略或执行器能力已变化，需要新的预授权。")
        if plan.risk_level not in grant.allowed_risk_levels:
            reasons.append("方案风险等级未被明确预授权。")
        if plan.requires_service_restart and not grant.allow_service_restart:
            reasons.append("可能的服务重启未被自动预授权。")
        if counters_known and (
            jobs_today >= grant.max_jobs_per_day or total_jobs >= grant.max_total_jobs
        ):
            reasons.append("自动修复已用完当日或本预授权的总任务配额。")
    return Decision(
        action="blocked" if reasons else "authorized",
        reasons=list(dict.fromkeys(reasons))
        or ["当前方案符合明确预授权、维护窗口及剩余任务配额。"],
        plan_digest=plan.plan_digest,
        mode=Mode.automatic,
        executable=not reasons,
    )


def re_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
