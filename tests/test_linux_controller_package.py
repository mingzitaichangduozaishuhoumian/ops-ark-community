"""Committed synthetic source packaging, never server or live credential data."""

import copy
import gzip
import hashlib
import io
import tarfile
from pathlib import Path

import linux_controller_package as package
import pytest
from test_release_bundle import source_commit as source_commit


def commit_more(repo):
    package._git(repo, "add", "--all")
    package._git(
        repo,
        "-c",
        "user.name=source-package-fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "controlled source",
    )
    return package._git(repo, "rev-parse", "HEAD").decode().strip()


@pytest.fixture
def controlled_commit(source_commit):
    repo, _ = source_commit
    # The imported official fixture deliberately dirties its worktree; restore
    # it before committing this separate, controlled test-source fixture.
    package._git(repo, "restore", "--", "web/index.html")
    (repo / "src/opsark/untracked.py").unlink()
    path = repo / "tools/release_bundle.py"
    path.parent.mkdir()
    path.write_bytes((Path(__file__).parents[1] / "tools/release_bundle.py").read_bytes())
    (repo / "tests").mkdir()
    (repo / "tests/test_fixture.py").write_bytes(b"def test_inert_source():\n    assert True\n")
    return repo, commit_more(repo)


def test_fixed_git_closure_includes_tests_excludes_data_and_ignores_worktree(
    tmp_path, controlled_commit
):
    repo, commit = controlled_commit
    (repo / "tests/test_fixture.py").write_bytes(b"working tree must never enter the package")
    (repo / "tests/untracked.py").write_bytes(b"not committed")
    first = package.build(repo, commit, tmp_path / "first")
    second = package.build(repo, commit, tmp_path / "second")
    assert first == second
    assert (tmp_path / "first/source.tar.gz").read_bytes() == (
        tmp_path / "second/source.tar.gz"
    ).read_bytes()
    names = {entry["path"] for entry in first["files"]}
    assert "tests/test_fixture.py" in names and "tools/release_bundle.py" in names
    assert "data/access-token" not in names and "tests/untracked.py" not in names
    assert package.read_identity(tmp_path / "first/identity.json") == first
    package.verify_package(tmp_path / "first/source.tar.gz", first)
    with tarfile.open(tmp_path / "first/source.tar.gz", "r:gz") as archive:
        stream = archive.extractfile("tests/test_fixture.py")
        assert stream is not None
        assert stream.read() == b"def test_inert_source():\n    assert True\n"
    with pytest.raises(package.PackageError, match="output_not_fresh"):
        package.build(repo, commit, tmp_path / "first")


def test_extracted_tree_and_official_candidate_match_then_detect_mutation(
    tmp_path, controlled_commit
):
    repo, commit = controlled_commit
    identity = package.build(repo, commit, tmp_path / "packages")
    root = tmp_path / "source"
    root.mkdir()
    with tarfile.open(tmp_path / "packages/source.tar.gz", "r:gz") as archive:
        archive.extractall(root, filter="data")
    before = package.verify_source_tree(root, identity)
    assert before["files"] == len(identity["files"])
    assert (
        package.verify_candidate(tmp_path / "packages/candidate.tar.gz", root, identity)["commit"]
        == commit
    )
    assert package.verify_source_tree(root, identity) == before
    (root / "tests/test_fixture.py").write_bytes(b"mutated source")
    with pytest.raises(package.PackageError, match="source_tree_digest_invalid"):
        package.verify_source_tree(root, identity)


@pytest.mark.parametrize("kind", ["symlink", "gitlink", "unreviewed_secret", "private_path"])
def test_selected_source_must_be_regular_public_code(tmp_path, controlled_commit, kind):
    repo, _ = controlled_commit
    if kind == "symlink":
        oid = (
            package._git(repo, "hash-object", "-w", "--stdin", input_data=b"../../outside")
            .decode()
            .strip()
        )
        package._git(
            repo, "update-index", "--add", "--cacheinfo", "120000," + oid + ",tests/link.py"
        )
    elif kind == "gitlink":
        oid = package._git(repo, "rev-parse", "HEAD").decode().strip()
        package._git(
            repo, "update-index", "--add", "--cacheinfo", "160000," + oid + ",tests/vendor"
        )
    else:
        name = (
            "tests/test_redaction.py" if kind == "unreviewed_secret" else "tests/secrets/example.py"
        )
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"marker = b'-----BEGIN OPENSSH PRIVATE KEY-----'\n")
        package._git(repo, "add", "--", name)
    package._git(
        repo,
        "-c",
        "user.name=source-package-fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "invalid selected source",
    )
    commit = package._git(repo, "rev-parse", "HEAD").decode().strip()
    with pytest.raises(package.PackageError):
        package.build(repo, commit, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_archive_duplicate_and_unsafe_identity_are_rejected(tmp_path, controlled_commit):
    repo, commit = controlled_commit
    identity = package.build(repo, commit, tmp_path / "packages")
    raw = gzip.decompress((tmp_path / "packages/source.tar.gz").read_bytes())
    modified = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as original,
        tarfile.open(
            fileobj=modified, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}
        ) as destination,
    ):
        first = None
        for member in original:
            data = None
            if member.isfile():
                stream = original.extractfile(member)
                assert stream is not None
                data = stream.read()
            destination.addfile(member, None if data is None else io.BytesIO(data))
            if member.isfile() and data is not None and first is None:
                first = (member, data)
        assert first is not None
        destination.addfile(first[0], io.BytesIO(first[1]))
    compressed = gzip.compress(modified.getvalue(), mtime=0)
    path = tmp_path / "duplicate.tar.gz"
    path.write_bytes(compressed)
    bad = copy.deepcopy(identity)
    bad.update(
        source_archive_bytes=len(compressed),
        source_archive_sha256=hashlib.sha256(compressed).hexdigest(),
    )
    with pytest.raises(package.PackageError, match="source_member_invalid"):
        package.verify_package(path, bad)
    invalid = copy.deepcopy(identity)
    invalid["files"][0]["path"] = "../escape.py"
    with pytest.raises(package.PackageError, match="source_path_invalid"):
        package.verify_package(tmp_path / "packages/source.tar.gz", invalid)


def test_complete_private_key_block_cannot_be_labeled_synthetic(
    tmp_path, controlled_commit, monkeypatch
):
    repo, _ = controlled_commit
    name = "tests/test_redaction.py"
    fake = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"A" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
    (repo / name).write_bytes(fake)
    monkeypatch.setitem(package.SYNTHETIC_EXCEPTIONS, name, hashlib.sha256(fake).hexdigest())
    commit = commit_more(repo)
    with pytest.raises(package.PackageError, match="private_key_block_refused"):
        package.build(repo, commit, tmp_path / "rejected")
