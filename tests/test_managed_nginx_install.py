"""Exercise root-owned registration using actual Linux filesystem metadata."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from test_managed_nginx_host import registration

from deploy.nginx import install_managed_helpers as installer

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0, reason="Requires isolated Linux root filesystem"
)


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory(prefix=".opsark-managed-install-", dir="/root") as folder:
        root = Path(folder)
        source, library = root / "source", root / "library"
        repo = Path(__file__).resolve().parents[1]
        for name in installer.HELPERS:
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((repo / name).read_bytes())
        assert installer.install(source, library)["status"] == "installed"
        yield library, root / "etc/nginx-action.json", root / "state/nginx-action"


def _policy(**updates):
    return json.dumps(registration() | updates).encode("utf-8")


def test_initialize_registers_exact_policy_and_preserves_action_history(workspace):
    library, policy, state = workspace
    approved = _policy()
    first = installer.initialize_state(library, approved, policy, state)
    assert first == {
        "status": "initialized",
        "policy_sha256": hashlib.sha256(approved).hexdigest(),
        "private_directory_count": 4,
    }
    assert policy.read_bytes() == approved and stat.S_IMODE(policy.stat().st_mode) == 0o600
    assert policy.stat().st_nlink == 1
    for name in installer.STATE_DIRECTORIES:
        info = (state / name).stat()
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
    history = state / "actions/history.fixture"
    history.write_bytes(b"synthetic history")
    policy_inode, history_inode = policy.stat().st_ino, history.stat().st_ino
    assert installer.initialize_state(library, approved, policy, state) == {
        **first,
        "status": "already_initialized",
    }
    with pytest.raises(ValueError, match="differs"):
        installer.initialize_state(library, _policy(to_port=18090), policy, state)
    assert policy.stat().st_ino == policy_inode and policy.read_bytes() == approved
    assert history.stat().st_ino == history_inode and history.read_bytes() == b"synthetic history"


def test_initialize_refuses_invalid_policy_and_unsafe_private_directory(workspace):
    library, policy, state = workspace
    with pytest.raises(subprocess.CalledProcessError):
        installer.initialize_state(library, _policy(enabled=False), policy, state)
    assert not policy.parent.exists() and not state.parent.exists()
    state.mkdir(parents=True)
    state.chmod(0o755)
    with pytest.raises(ValueError, match="ownership or mode"):
        installer.initialize_state(library, _policy(), policy, state)
    assert not policy.exists() and stat.S_IMODE(state.stat().st_mode) == 0o755


def test_policy_source_requires_matching_digest_and_private_mode(workspace):
    _, policy, _ = workspace
    source = policy.parent.parent / "approved.fixture"
    approved = _policy()
    source.write_bytes(approved)
    source.chmod(0o600)
    arguments = ["--policy", str(source), "--policy-sha256", hashlib.sha256(approved).hexdigest()]
    assert installer._requested_policy(arguments) == approved
    with pytest.raises(ValueError, match="digest"):
        installer._requested_policy([*arguments[:3], "0" * 64])
    source.chmod(0o644)
    with pytest.raises(ValueError, match="Untrusted helper file"):
        installer._requested_policy(arguments)


def test_atomic_publication_refuses_an_existing_destination(workspace):
    _, policy, _ = workspace
    source = policy.parent.parent / "source.fixture"
    destination = source.with_name("other.fixture")
    source.write_bytes(b"prepared")
    destination.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        installer._rename_new(source, destination)
    assert source.read_bytes() == b"prepared" and destination.read_bytes() == b"existing"
