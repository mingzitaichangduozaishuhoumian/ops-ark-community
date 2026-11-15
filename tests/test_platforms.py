from datetime import UTC, datetime

import pytest

from opsark.diagnostics import diagnose
from opsark.models import CheckResult, Collection, HostPublic, Report
from opsark.platforms import TOOLS, assess, os_identity, tool_identity
from opsark.replay import collect_replay


def probes(system="ubuntu", architecture="x86_64"):
    return [
        CheckResult(name="os_release", stdout=f'ID={system}\nVERSION_ID="24.04"\n'),
        CheckResult(
            name="platform_tools",
            stdout=f"OPSARK_ARCH={architecture}\n"
            + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS),
        ),
    ]


@pytest.mark.parametrize("system", ["ubuntu", "debian"])
@pytest.mark.parametrize("architecture", ["x86_64", "aarch64"])
def test_matching_adapter_reports_probe_scope_not_machine_validation(system, architecture):
    result = assess(probes(system, architecture))
    assert result.status == "compatible"
    assert result.os_id == system
    assert result.architecture == architecture
    assert result.adapter == "ubuntu_debian"
    assert "不代表该版本已通过实机验收" in result.detail
    assert set(result.evidence_ids) == {"E-OS-RELEASE", "E-PLATFORM-TOOLS"}


@pytest.mark.parametrize(
    "raw",
    [
        "ID=ubuntu\nID=fedora\n",
        "ID='ubuntu\"\n",
        "ID=$(id)\n",
        "ID=ubuntu;id\n",
        'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_ID="22.04"\n',
        "ID_LIKE=ubuntu\n",
    ],
)
def test_ambiguous_or_shell_like_identity_is_not_treated_as_supported(raw):
    assert os_identity(CheckResult(name="os_release", stdout=raw))[0] is None


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "error"},
        {"exit_code": 1},
        {"truncated": True},
        {"status": "permission_denied"},
    ],
)
def test_incomplete_system_evidence_never_selects_adapter(changes):
    results = probes()
    results[0] = results[0].model_copy(update=changes)
    assert assess(results).status == "unknown"


def test_missing_tools_do_not_claim_service_permissions():
    results = probes()
    results[1].stdout = results[1].stdout.replace("OPSARK_TOOL_docker=1", "OPSARK_TOOL_docker=0")
    assessment = assess(results)
    assert assessment.status == "compatible"
    assert assessment.missing_tools == ["docker"]
    assert "docker" not in assessment.available_tools
    assert "不证明权限" in assessment.detail


@pytest.mark.parametrize(
    "raw",
    [
        "OPSARK_ARCH=x86_64\n",
        "OPSARK_ARCH=x86_64\nOPSARK_TOOL_df=yes\n",
        "OPSARK_ARCH=$(uname -m)\n",
        "random banner\n",
    ],
)
def test_incomplete_or_injected_tool_protocol_does_not_match(raw):
    assert tool_identity(CheckResult(name="platform_tools", stdout=raw)) == (None, {})


def test_duplicate_tool_markers_and_truncation_cannot_select_adapter():
    results = probes()
    results[1].stdout += "OPSARK_TOOL_df=1\n"
    assert assess(results).status == "unknown"
    results = probes()
    results[1].truncated = True
    assert assess(results).status == "unknown"


def test_derived_distributions_and_unadapted_architectures_stop():
    assert assess(probes("linuxmint")).status == "unsupported"
    assert assess(probes(architecture="armv7l")).status == "unsupported"


def test_real_ssh_source_requires_preflight_even_with_healthy_looking_outputs():
    host, collection = collect_replay("disk-healthy")
    host.source = "ssh"
    collection.source = "ssh"
    report = diagnose("disk", host, collection)
    assert report.status == "inconclusive"
    assert report.compatibility.status == "unknown"
    assert not any("根分区容量快照" in item.text for item in report.facts)


def test_unknown_os_and_missing_tools_remain_traceable_in_report():
    host = HostPublic(id="probe", name="Probe", address="192.0.2.10", source="ssh")
    report = diagnose(
        "disk",
        host,
        Collection(
            host_id=host.id,
            source="ssh",
            started_at=datetime.now(UTC),
            checks=probes("fedora"),
        ),
    )
    assert report.compatibility.status == "unsupported"
    assert set(report.compatibility.evidence_ids) <= {item.id for item in report.evidence}
    assert not report.action.executable


def test_old_report_loads_with_explicitly_unknown_preflight():
    host, collection = collect_replay("disk-healthy")
    report = diagnose("disk", host, collection)
    payload = report.model_dump(exclude={"compatibility"})
    assert Report.model_validate(payload).compatibility.detail == "旧报告未包含环境预检。"


@pytest.mark.parametrize("probe_change", ["unsupported", "malformed"])
def test_replay_cannot_override_an_explicit_incompatible_probe(probe_change):
    host, collection = collect_replay("disk-healthy")
    tools = probes(architecture="s390x" if probe_change == "unsupported" else "x86_64")[1]
    if probe_change == "malformed":
        tools.stdout += "unexpected banner\n"
    collection.checks.append(tools)
    report = diagnose("disk", host, collection)
    assert report.status == "inconclusive"
    assert not any("根分区容量快照" in finding.text for finding in report.facts)
