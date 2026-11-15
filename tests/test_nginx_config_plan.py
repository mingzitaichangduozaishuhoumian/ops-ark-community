"""Private Nginx change plans against actual Linux files and their identities."""

import hashlib
import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple

import pytest
from test_nginx_config_snapshot import CONTENT, DIGEST, snapshot_tool
from test_nginx_config_snapshot import tree as tree

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux directory and file trust rules"
)

PLAN_CANARY = "PRIVATE-NGINX-PLAN-CANARY"
CANDIDATE = f'server {{ set $upstream_key "{PLAN_CANARY}"; }}\n'.encode()
CANDIDATE_DIGEST = hashlib.sha256(CANDIDATE).hexdigest()
CREATED = datetime(2026, 11, 5, 12, 30, tzinfo=UTC)


class ConfigPlanFiles(NamedTuple):
    source: Path
    backup: Path
    candidate: Path
    output: Path
    policy: snapshot_tool.SnapshotPolicy


@pytest.fixture
def plan_files(tree, tmp_path):
    source, backup, policy = tree
    snapshot_tool.capture(source, DIGEST, backup, policy=policy)
    candidates = tmp_path / "candidates"
    candidates.mkdir(mode=0o700)
    candidate = candidates / source.name
    candidate.write_bytes(CANDIDATE)
    candidate.chmod(0o600)
    return ConfigPlanFiles(source, backup, candidate, backup.parent / "plan", policy)


def prepare(files, expected=CANDIDATE_DIGEST):
    return snapshot_tool.prepare(
        files.backup, files.candidate, expected, files.output, policy=files.policy, now=CREATED
    )


def inspect(files, now=CREATED):
    return snapshot_tool.inspect_plan(files.output, policy=files.policy, now=now)


def test_prepare_binds_private_candidate_backup_and_live_source(plan_files, capsys):
    files = plan_files
    manifest_before = (files.backup / "manifest.json").read_bytes()
    source_before = files.source.stat()
    candidate_before = files.candidate.stat()
    result = prepare(files)
    assert result == inspect(files)
    assert set(result) == {
        "schema_version",
        "plan_status",
        "syntax_status",
        "approval_status",
        "plan_id",
        "candidate_sha256",
        "expires_at",
    }
    assert result["schema_version"] == 1
    assert result["plan_status"] == "ready"
    assert result["syntax_status"] == "not_checked"
    assert result["approval_status"] == "not_approved"
    assert result["candidate_sha256"] == CANDIDATE_DIGEST
    assert datetime.fromisoformat(result["expires_at"]) == CREATED + timedelta(minutes=10)
    assert len(result["plan_id"]) == 32 and int(result["plan_id"], 16) > 0
    assert {path.name for path in files.output.iterdir()} == {"candidate.conf", "manifest.json"}
    assert (
        (files.output / "candidate.conf").read_bytes() == CANDIDATE == files.candidate.read_bytes()
    )
    assert files.source.read_bytes() == CONTENT == (files.backup / "nginx.conf").read_bytes()
    assert (files.backup / "manifest.json").read_bytes() == manifest_before
    assert stat.S_IMODE(files.output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files.output.iterdir())
    assert files.source.stat().st_ctime_ns == source_before.st_ctime_ns
    assert files.candidate.stat().st_ctime_ns == candidate_before.st_ctime_ns
    stdout, stderr = capsys.readouterr()
    public = json.dumps(result) + stdout + stderr
    assert PLAN_CANARY not in public and str(files.backup) not in public
    assert str(files.candidate) not in public and str(files.source) not in public
    assert PLAN_CANARY not in (files.output / "manifest.json").read_text()


@pytest.mark.parametrize("cause", ["stale_backup", "tampered_backup", "candidate_mismatch"])
def test_prepare_refuses_unbound_inputs_without_publishing(plan_files, cause):
    files = plan_files
    if cause == "stale_backup":
        files.source.write_bytes(CONTENT + b"# live changed before prepare\n")
    elif cause == "tampered_backup":
        (files.backup / "nginx.conf").write_bytes(CONTENT + b"# backup tamper\n")
    else:
        files.candidate.write_bytes(CANDIDATE + b"# differs from approved hash\n")
    protected = (files.source, files.candidate, files.backup / "nginx.conf")
    before = {path: path.read_bytes() for path in protected}
    with pytest.raises(snapshot_tool.SnapshotError) as error:
        prepare(files)
    assert PLAN_CANARY not in str(error.value)
    assert not files.output.exists()
    assert {path: path.read_bytes() for path in protected} == before


@pytest.mark.parametrize("target", ["source", "candidate", "backup"])
def test_prepare_refuses_changes_during_publication(plan_files, target, monkeypatch):
    files = plan_files
    changed = {
        "source": files.source,
        "candidate": files.candidate,
        "backup": files.backup / "nginx.conf",
    }[target]
    external_content = changed.read_bytes() + b"# changed while preparing\n"
    write = snapshot_tool._write

    def write_during_change(parent, name, data):
        write(parent, name, data)
        if name == "candidate.conf":
            changed.write_bytes(external_content)

    monkeypatch.setattr(snapshot_tool, "_write", write_during_change)
    with pytest.raises(snapshot_tool.SnapshotError):
        prepare(files)
    assert not files.output.exists()
    assert changed.read_bytes() == external_content


def test_candidate_copy_is_independent_and_only_the_plan_copy_is_verified(plan_files):
    files = plan_files
    intact = prepare(files)
    files.candidate.write_bytes(CANDIDATE + b"# later draft change\n")
    assert inspect(files) == intact
    staged = files.output / "candidate.conf"
    assert staged.read_bytes() == CANDIDATE
    staged.write_bytes(CANDIDATE + b"# altered plan copy\n")
    assert inspect(files) == {
        "schema_version": 1,
        "plan_status": "tampered",
        "syntax_status": "not_checked",
        "approval_status": "not_approved",
    }
    assert staged.read_bytes() == CANDIDATE + b"# altered plan copy\n"
    assert files.source.read_bytes() == CONTENT


def test_plan_manifest_tamper_withholds_metadata(plan_files):
    files = plan_files
    prepare(files)
    marker = files.output / "manifest.json"
    manifest = json.loads(marker.read_bytes())
    manifest.pop("manifest_sha256")
    manifest["expires_at"] = (CREATED + timedelta(days=1)).isoformat()
    forged_content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = hashlib.sha256(forged_content).hexdigest()
    marker.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    result = inspect(files)
    assert result["plan_status"] == "tampered"
    assert not {"plan_id", "candidate_sha256", "expires_at"} & result.keys()
    assert (files.output / "candidate.conf").read_bytes() == CANDIDATE


@pytest.mark.parametrize(
    ("cause", "expected"),
    [
        ("changed_bytes", "drift"),
        ("replaced_file", "drift"),
        ("missing_live", "unavailable"),
        ("missing_backup", "unavailable"),
    ],
)
def test_inspect_distinguishes_live_drift_and_missing_evidence(plan_files, cause, expected):
    files = plan_files
    initial = prepare(files)
    if cause == "changed_bytes":
        files.source.write_bytes(CONTENT + b"# live changed after prepare\n")
    elif cause == "replaced_file":
        replacement = files.source.with_name("replacement.conf")
        replacement.write_bytes(CONTENT)
        replacement.chmod(0o640)
        replacement.replace(files.source)
    elif cause == "missing_live":
        files.source.unlink()
    else:
        (files.backup / "manifest.json").unlink()
    assert inspect(files) == {**initial, "plan_status": expected}
    assert (files.output / "candidate.conf").read_bytes() == CANDIDATE


def test_plan_expires_without_changing_source_or_private_artifacts(plan_files):
    files = plan_files
    initial = prepare(files)
    expiry = CREATED + timedelta(minutes=10)
    manifest = (files.output / "manifest.json").read_bytes()
    assert inspect(files, CREATED - timedelta(microseconds=1)) == {
        **initial,
        "plan_status": "unavailable",
    }
    assert inspect(files, expiry - timedelta(microseconds=1)) == initial
    assert inspect(files, expiry) == {**initial, "plan_status": "expired"}
    assert files.source.read_bytes() == CONTENT
    assert (files.output / "candidate.conf").read_bytes() == CANDIDATE
    assert (files.output / "manifest.json").read_bytes() == manifest
