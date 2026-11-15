"""Bounded evidence contracts for continuous, observation-only SSH security."""

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from opsark.models import StrictModel


class SecurityEvent(StrictModel):
    id: str = Field(pattern=r"^[0-9a-f]{64}$")
    host_id: str
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    origin: Literal["system_ssh", "controlled_probe"]
    kind: Literal["authentication_failed", "authentication_accepted"]
    source_ip: str
    method: Literal["password", "publickey", "keyboard-interactive"]
    account_type: Literal["root", "invalid", "other"]
    journal_cursor: str = Field(min_length=1, max_length=256)
    unit: Literal["ssh.service", "opsark-security-probe.service"]


class SecurityObservation(StrictModel):
    id: str
    host_id: str
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    collected_at: datetime
    window_started_at: datetime
    window_ended_at: datetime
    status: Literal["complete", "degraded", "unavailable"]
    events: list[SecurityEvent] = Field(default_factory=list, max_length=80)
    gaps: list[str] = Field(default_factory=list, max_length=20)
    raw_records_seen: int = Field(default=0, ge=0, le=10000)
    duration_ms: int = Field(default=0, ge=0)


class AcknowledgeAlert(StrictModel):
    acknowledge: Literal[True]


class SecurityAnalysisRequest(StrictModel):
    confirm_send: bool = Field(strict=True)
    expected_input_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)

    @field_validator("confirm_send")
    @classmethod
    def explicit_consent(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("必须明确确认发送当前摘要。")
        return value
