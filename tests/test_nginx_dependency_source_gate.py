"""Exact reviewed synthetic-canary source acceptance; no credential literals."""

import hashlib
from pathlib import Path

import linux_controller_package as package
import pytest
from test_linux_controller_package import commit_more
from test_linux_controller_package import controlled_commit as controlled_commit
from test_release_bundle import source_commit as source_commit


def test_reviewed_nginx_canary_exception_is_bound_to_exact_test_bytes(tmp_path, controlled_commit):
    repo, _ = controlled_commit
    name = "tests/test_nginx_dependencies.py"
    raw = (Path(__file__).parent / "test_nginx_dependencies.py").read_bytes()
    assert not package.KEY_BLOCK.search(raw)
    assert package.SYNTHETIC_EXCEPTIONS[name] == hashlib.sha256(raw).hexdigest()
    (repo / name).write_bytes(raw)
    commit = commit_more(repo)
    package.build(repo, commit, tmp_path / "reviewed-canary")
    (repo / name).write_bytes(raw + b"\n# changed source requires another independent review\n")
    changed = commit_more(repo)
    with pytest.raises(package.PackageError, match="unreviewed_private_source_marker"):
        package.build(repo, changed, tmp_path / "changed-canary-rejected")
