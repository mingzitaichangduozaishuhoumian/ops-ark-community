"""Shared contracts for collection, analysis, persistence and the web console."""

import re
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Scenario = Literal["web_502", "disk", "container_restart", "ssh_security"]
Source = Literal["replay", "ssh"]
CheckStatus = Literal["ok", "error", "timeout", "permission_denied", "unavailable"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthCheck(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$")
    port: int = Field(default=80, ge=1, le=65535, strict=True)
    path: str = Field(default="/healthz", pattern=r"^/[A-Za-z0-9/_.-]*$", max_length=200)
    expected_status: int = Field(default=200, ge=200, le=299, strict=True)
    expected_body: str = Field(default="", max_length=160)
    read_only_confirmed: bool = Field(default=False, strict=True)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        if value.startswith("//") or any(part in {".", ".."} for part in value.split("/")):
            raise ValueError("检查路径不能包含路径跳转或协议相对地址。")
        return value


class BusinessCheck(StrictModel):
    """Private registration for a target-side, exact-response comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    domain: str = Field(min_length=1, max_length=253)
    port: int = Field(default=80, ge=1, le=65535)
    path: str = Field(max_length=256)
    expected_status: int = Field(default=200, ge=200, le=299)
    expected_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    read_only_confirmed: bool = False

    @field_validator("domain")
    @classmethod
    def safe_domain(cls, value: str) -> str:
        label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if any(re.fullmatch(label, part) is None for part in value.split(".")):
            raise ValueError("业务检查需要有效的 ASCII 域名。")
        return value

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        if (
            re.fullmatch(r"/[A-Za-z0-9._~/-]*", value) is None
            or "//" in value
            or any(part in {".", ".."} for part in value.split("/"))
        ):
            raise ValueError("业务检查路径需要安全的本机只读路径。")
        return value


class HostPublic(StrictModel):
    id: str
    name: str
    address: str
    port: int = 22
    username: str = "opsark-readonly"
    site_domain: str = "shop.example.com"
    container_name: str = "api"
    expected_upstream_port: int = 8081
    source: Source = "replay"
    health_checks: list[HealthCheck] = Field(default_factory=list, max_length=3)
    nginx_config_path: str | None = None
    trusted_hosts_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    web_profile_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", strict=True)
    disk_reclaim_scope_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$", strict=True
    )

    @field_validator("health_checks")
    @classmethod
    def unique_checks(cls, value: list[HealthCheck]) -> list[HealthCheck]:
        if len({item.id for item in value}) != len(value):
            raise ValueError("同一主机的检查标识不能重复。")
        return value

    @field_validator("nginx_config_path")
    @classmethod
    def registered_config(cls, value: str | None) -> str | None:
        if value is not None and (
            ".." in value
            or not re.fullmatch(
                r"/etc/nginx/(?:sites-available|conf\.d)/[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", value
            )
        ):
            raise ValueError("配置摘要只接受登记的 Nginx 目录内单个安全文件名。")
        return value


class CheckResult(StrictModel):
    name: str
    status: CheckStatus = "ok"
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = 0
    duration_ms: int = 0
    truncated: bool = False


class NginxErrorWindow(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    status: Literal["observed", "permission_denied", "source_missing", "inconclusive"]
    reason: (
        Literal[
            "coverage_unconfirmed",
            "source_untrusted",
            "source_changed",
            "clock_unconfirmed",
            "read_unconfirmed",
        ]
        | None
    )
    observed_at: AwareDatetime
    window_seconds: Literal[900]
    matching_refused: int | None = Field(ge=0, le=512)
    matching_timeout: int | None = Field(ge=0, le=512)

    @field_validator("observed_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def check_scope(self) -> Self:
        if self.status == "observed":
            if (
                self.reason is not None
                or self.matching_refused is None
                or self.matching_timeout is None
                or self.matching_refused + self.matching_timeout > 512
            ):
                raise ValueError("Invalid Nginx observation counts")
        elif (
            self.matching_refused is not None
            or self.matching_timeout is not None
            or (self.status == "inconclusive") != (self.reason is not None)
        ):
            raise ValueError("Incomplete Nginx observation cannot contain counts")
        return self


class Collection(StrictModel):
    host_id: str
    source: Source
    started_at: datetime
    checks: list[CheckResult]
    duration_ms: int = 0
    nginx_error_window: NginxErrorWindow | None = Field(
        default=None, exclude_if=lambda v: v is None
    )
    nginx_error_window_blocked: bool = Field(default=False, exclude=True)


class Evidence(StrictModel):
    id: str
    check_id: str
    target: str
    source: Source
    collected_at: datetime
    status: CheckStatus
    output: str
    exit_code: int | None = None
    truncated: bool = False


class Finding(StrictModel):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class ActionBoundary(StrictModel):
    executable: Literal[False] = False
    reason: str = "本调查只采集证据并提供建议；补丁修复需另行生成并批准具体任务。"


class Verification(StrictModel):
    name: str
    status: Literal["not_run", "uncovered", "passed", "failed", "error"] = "not_run"
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)
    http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    status_matches: bool | None = Field(default=None, strict=True)
    body_matches: bool | None = Field(default=None, strict=True)


class BaselineChange(StrictModel):
    field: str
    before: str
    after: str
    evidence_ids: list[str] = Field(default_factory=list)


class BaselineComparison(StrictModel):
    status: Literal["no_baseline", "compared", "incomplete", "scope_changed"] = "no_baseline"
    baseline_id: str | None = None
    baseline_report_id: str | None = None
    baseline_created_at: datetime | None = None
    changes: list[BaselineChange] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    purpose: Literal["observation_only"] = "observation_only"
    restore_capable: Literal[False] = False


class BaselineInfo(StrictModel):
    id: str
    report_id: str
    host_id: str
    source: Source
    scenario: Scenario
    created_at: datetime
    scope_hash: str
    features: dict[str, str]
    references: dict[str, list[str]]
    missing: list[str] = Field(default_factory=list)
    schema_version: int = Field(default=0, ge=0, strict=True)
    purpose: Literal["observation_only"] = "observation_only"
    restore_capable: Literal[False] = False


class AIExplanation(StrictModel):
    status: Literal["not_requested", "disabled", "completed", "failed"] = "not_requested"
    text: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    model: str | None = None


class CompatibilityAssessment(StrictModel):
    status: Literal["compatible", "unsupported", "unknown"] = "unknown"
    os_id: str | None = None
    version_id: str | None = None
    architecture: str | None = None
    adapter: str | None = None
    available_tools: list[str] = Field(default_factory=list)
    missing_tools: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    detail: str = "旧报告未包含环境预检。"


class Report(StrictModel):
    id: str
    host_id: str
    host_name: str
    scenario: Scenario
    source: Source
    created_at: datetime
    status: Literal["needs_attention", "inconclusive", "no_issue_detected"]
    title: str
    summary: str
    facts: list[Finding]
    candidates: list[Finding]
    missing: list[str]
    evidence: list[Evidence]
    next_steps: list[str]
    action: ActionBoundary = Field(default_factory=ActionBoundary)
    verification: list[Verification] = Field(default_factory=list)
    ai: AIExplanation = Field(default_factory=AIExplanation)
    ai_egress_block_reason: (
        Literal["sensitive_content", "unclassified_payload", "input_budget_exceeded"] | None
    ) = None
    duration_ms: int = 0
    scope_hash: str = ""
    comparison: BaselineComparison = Field(default_factory=BaselineComparison)
    target: HostPublic | None = None
    compatibility: CompatibilityAssessment = Field(default_factory=CompatibilityAssessment)
    nginx_error_window: NginxErrorWindow | None = Field(
        default=None, exclude_if=lambda v: v is None
    )


class HostPreflightRequest(StrictModel):
    """An explicit preflight action accepts no settings from the caller."""


class InvestigationRequest(StrictModel):
    source: Source = "replay"
    scenario: Scenario
    sample_id: str | None = Field(default=None, max_length=80)
    host_id: str | None = Field(default=None, max_length=80)


class ExplainRequest(StrictModel):
    confirm_send: Literal[True]


class BaselineRequest(StrictModel):
    confirm_observation_only: Literal[True]
