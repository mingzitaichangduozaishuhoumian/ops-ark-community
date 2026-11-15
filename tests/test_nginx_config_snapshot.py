"""Offline Nginx backup tests against actual POSIX files and file identities."""

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "opsark_nginx_config_snapshot",
    Path(__file__).resolve().parents[1] / "deploy/nginx/config_snapshot.py",
)
assert SPEC is not None and SPEC.loader is not None
snapshot_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = snapshot_tool
SPEC.loader.exec_module(snapshot_tool)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux directory and file trust rules"
)

CANARY = "PRIVATE-NGINX-CONFIG-CANARY"
CONTENT = f'server {{ set $upstream_key "{CANARY}"; }}\n'.encode()
DIGEST = hashlib.sha256(CONTENT).hexdigest()


@pytest.fixture
def tree(tmp_path):
    tmp_path.chmod(0o700)
    nginx_root = tmp_path / "nginx"
    nginx_root.mkdir(mode=0o700)
    config = nginx_root / "conf.d"
    config.mkdir(mode=0o700)
    source = config / "site.conf"
    source.write_bytes(CONTENT)
    source.chmod(0o640)
    machine = tmp_path / "machine-id"
    machine.write_bytes(b"0123456789abcdef0123456789abcdef\n")
    machine.chmod(0o600)
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700)
    policy = snapshot_tool.SnapshotPolicy(
        anchor=tmp_path, config_directory=config, machine_id=machine, owner_uid=os.geteuid()
    )
    return source, backups / "snapshot", policy


def receipt(*, disk="unchanged", intact=True):
    result = {
        "schema_version": 1,
        "backup_integrity": "intact" if intact else "tampered",
        "disk_status": disk,
        "rollback_status": "not_rehearsed",
    }
    if intact:
        result["sha256"] = DIGEST
    return result


def capture(tree):
    source, output, policy = tree
    return snapshot_tool.capture(source, DIGEST, output, policy=policy)


def inspect(tree):
    _, output, policy = tree
    return snapshot_tool.inspect(output, policy=policy)


def test_capture_writes_exact_private_backup_and_reports_only_metadata(tree, capsys):
    source, output, _policy = tree
    before = source.stat()
    first = capture(tree)
    assert first == inspect(tree) == receipt()
    assert {p.name for p in output.iterdir()} == {"nginx.conf", "manifest.json"}
    assert (output / "nginx.conf").read_bytes() == CONTENT == source.read_bytes()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in output.iterdir())
    after = source.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_mode) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    assert CANARY not in json.dumps(first)
    assert CANARY not in (output / "manifest.json").read_text()
    stdout, stderr = capsys.readouterr()
    assert CANARY not in stdout + stderr


def test_capture_requires_exact_current_digest(tree):
    source, output, policy = tree
    source.write_bytes(CONTENT + b"# external drift\n")
    expected_source = source.read_bytes()
    with pytest.raises(snapshot_tool.SnapshotError) as error:
        snapshot_tool.capture(source, DIGEST, output, policy=policy)
    assert CANARY not in str(error.value)
    assert source.read_bytes() == expected_source
    assert not output.exists()


def test_capture_discards_backup_if_source_changes_before_publication(tree, monkeypatch):
    source, output, _policy = tree
    original_write = snapshot_tool._write
    new_content = CONTENT + b"# changed after staging started\n"

    def write_during_edit(parent, name, data):
        original_write(parent, name, data)
        if name == "nginx.conf":
            source.write_bytes(new_content)

    monkeypatch.setattr(snapshot_tool, "_write", write_during_edit)
    with pytest.raises(snapshot_tool.SnapshotError):
        capture(tree)
    assert not output.exists()
    assert source.read_bytes() == new_content


@pytest.mark.parametrize("edit", ["content", "same_bytes_replacement", "mode"])
def test_inspection_marks_live_drift_without_overwriting_source(tree, edit):
    source, output, _policy = tree
    capture(tree)
    if edit == "content":
        source.write_bytes(CONTENT + b"# externally edited\n")
    elif edit == "same_bytes_replacement":
        replacement = source.with_name("replacement.conf")
        replacement.write_bytes(CONTENT)
        replacement.chmod(0o640)
        replacement.replace(source)
    else:
        source.chmod(0o600)
    expected_source = source.read_bytes()
    expected_mode = source.stat().st_mode
    assert inspect(tree) == receipt(disk="drift")
    assert source.read_bytes() == expected_source
    assert source.stat().st_mode == expected_mode
    assert (output / "nginx.conf").read_bytes() == CONTENT


@pytest.mark.parametrize("cause", ["missing", "linked", "machine_changed"])
def test_backup_is_still_intact_if_live_identity_cannot_be_checked(tree, cause):
    source, output, policy = tree
    capture(tree)
    if cause == "missing":
        source.unlink()
    elif cause == "linked":
        target = source.with_name("other.conf")
        source.rename(target)
        source.symlink_to(target)
    else:
        policy.machine_id.write_bytes(b"fedcba9876543210fedcba9876543210\n")
    assert inspect(tree) == receipt(disk="unavailable")
    assert (output / "nginx.conf").read_bytes() == CONTENT


@pytest.mark.parametrize("part", ["payload", "manifest", "linked_payload", "extra"])
def test_tampered_archive_is_refused_without_repairing_it(tree, part):
    source, output, _policy = tree
    capture(tree)
    backup = output / "nginx.conf"
    if part == "payload":
        backup.write_bytes(CONTENT.replace(b"CANARY", b"ALTERD"))
    elif part == "manifest":
        (output / "manifest.json").write_bytes(b'{"schema_version":1,"schema_version":1}\n')
    elif part == "linked_payload":
        backup.unlink()
        backup.symlink_to(source)
    else:
        (output / "unexpected-key").write_text(CANARY)
    names_before = {p.name for p in output.iterdir()}
    assert inspect(tree) == receipt(disk="unavailable", intact=False)
    assert {p.name for p in output.iterdir()} == names_before
    assert source.read_bytes() == CONTENT


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "unsafe_mode"])
def test_capture_refuses_untrusted_configuration_file(tree, kind):
    source, output, _policy = tree
    if kind == "symlink":
        real = source.with_name("real.conf")
        source.rename(real)
        source.symlink_to(real)
    elif kind == "hardlink":
        os.link(source, source.with_name("other.conf"))
    else:
        source.chmod(0o666)
    with pytest.raises(snapshot_tool.SnapshotError):
        capture(tree)
    assert not output.exists()


@pytest.mark.parametrize("destination", ["existing", "linked_parent"])
def test_capture_does_not_replace_destination(tree, destination):
    source, output, policy = tree
    if destination == "existing":
        output.mkdir(mode=0o700)
        prior = output / "nginx.conf"
        prior.write_bytes(b"previous snapshot")
        with pytest.raises(snapshot_tool.SnapshotError):
            capture(tree)
        assert prior.read_bytes() == b"previous snapshot"
        assert list(output.iterdir()) == [prior]
    else:
        link = output.parent.with_name("linked-backups")
        link.symlink_to(output.parent, target_is_directory=True)
        with pytest.raises(snapshot_tool.SnapshotError):
            snapshot_tool.capture(source, DIGEST, link / output.name, policy=policy)
        assert not output.exists()
