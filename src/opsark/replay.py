"""Load explicitly fictional raw collections through a fixed fixture allowlist."""

from datetime import UTC, datetime
from pathlib import Path

from opsark.models import CheckResult, Collection, HostPublic, Scenario, StrictModel

_DIRECTORY = Path(__file__).with_name("fixtures")
_FILES = {
    name: _DIRECTORY / f"{name}.json"
    for name in (
        "web-port-mismatch",
        "web-upstream-stopped",
        "web-permission-denied",
        "disk-capacity-full",
        "disk-inode-full",
        "disk-healthy",
        "container-oom",
        "container-exit-137-unknown",
        "container-healthy",
        "ssh-repeated-failures",
        "ssh-ordinary-logins",
        "collection-unavailable",
    )
}


class _Fixture(StrictModel):
    title: str
    scenario: Scenario
    host: HostPublic
    checks: list[CheckResult]


def _load(sample_id: str) -> _Fixture:
    # Do not construct a path from user input, even after path normalization.
    if sample_id not in _FILES:
        raise KeyError(sample_id)
    fixture = _Fixture.model_validate_json(_FILES[sample_id].read_text(encoding="utf-8"))
    if fixture.host.source != "replay":
        raise ValueError("a replay fixture cannot declare a live source")
    return fixture


def list_samples() -> list[dict[str, str]]:
    """Describe synthetic examples without exposing filenames or credentials."""
    return [
        {
            "id": sample_id,
            "title": fixture.title,
            "scenario": fixture.scenario,
            "host_id": fixture.host.id,
        }
        for sample_id in _FILES
        for fixture in [_load(sample_id)]
    ]


def collect_replay(sample_id: str) -> tuple[HostPublic, Collection]:
    """Read a fresh fixture copy; the timestamp is replay-read time, not SSH time."""
    fixture = _load(sample_id)
    return fixture.host, Collection(
        host_id=fixture.host.id,
        source="replay",
        started_at=datetime.now(UTC),
        checks=fixture.checks,
        duration_ms=0,
    )
