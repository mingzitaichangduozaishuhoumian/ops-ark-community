"""Reduced, bounded Web evidence; raw requests never cross this contract."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from opsark.models import StrictModel

WebOrigin = Literal["system_web", "controlled_web_probe"]
WebSourceTrust = Literal["direct_peer", "trusted_proxy", "unresolved_proxy", "forwarded_ignored"]
WebPathClass = Literal[
    "health",
    "normal",
    "static",
    "robots",
    "callback",
    "secret_probe",
    "repo_probe",
    "cms_probe",
    "admin_probe",
    "traversal_probe",
    "other",
]


class WebSecurityEvent(StrictModel):
    id: str = Field(pattern=r"^[0-9a-f]{64}$")
    host_id: str
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    channel: Literal["web"] = "web"
    kind: Literal["web_request"] = "web_request"
    origin: WebOrigin
    site_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    source_ip: str | None
    peer_ip: str
    source_trust: WebSourceTrust
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER"]
    status: int = Field(ge=100, le=599, strict=True)
    path_class: WebPathClass
    client_class: Literal["browser", "declared_crawler", "probe", "other"]
    request_time_ms: int = Field(ge=0, le=60_000, strict=True)
    bytes_sent: int = Field(ge=0, le=2**63 - 1, strict=True)
    journal_cursor: str = Field(min_length=1, max_length=256)
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    expected_error: bool = Field(default=False, strict=True)


class WebSecurityObservation(StrictModel):
    id: str
    host_id: str
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    channel: Literal["web"] = "web"
    collected_at: datetime
    window_started_at: datetime
    window_ended_at: datetime
    status: Literal["complete", "degraded", "unavailable"]
    events: list[WebSecurityEvent] = Field(default_factory=list, max_length=80)
    gaps: list[str] = Field(default_factory=list, max_length=20)
    raw_records_seen: int = Field(default=0, ge=0, le=10_000)
    duration_ms: int = Field(default=0, ge=0)


WebEvent = WebSecurityEvent
