"""Committed release sources can be verified locally without extracting an archive."""

import gzip
import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "opsark_release_bundle", Path(__file__).resolve().parents[1] / "tools/release_bundle.py"
)
assert SPEC is not None and SPEC.loader is not None
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


@pytest.fixture
def source_commit(tmp_path):
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is required to build a committed fixture")
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(  # noqa: S603 - isolated local fixture, no shell
            [executable, "-C", str(repo), "-c", "core.autocrlf=false", *args],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    git("init", "--template=", "-q")
    version_files = {
        "pyproject.toml": '[project]\nname = "ops-ark"\nversion = "0.17.0"\n',
        "uv.lock": (
            '[[package]]\nname = "ops-ark"\nversion = "0.17.0"\nsource = { virtual = "." }\n'
        ),
        "src/opsark/__init__.py": '__version__ = "0.17.0"\n',
    }
    excluded = {"data/access-token", "opsark.local.toml", "docs/PERSISTENT_CONTROL.md"}
    for name in bundle.REQUIRED | excluded:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = version_files.get(name, "committed fixture\n")
        path.write_bytes(content.encode())
    git("add", "--all")
    git(
        "-c",
        "user.name=OpsArk release test",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    )
    commit = git("rev-parse", "HEAD")
    (repo / "web/index.html").write_text("working tree only", encoding="utf-8")
    (repo / "src/opsark/untracked.py").write_text("untracked marker", encoding="utf-8")
    return repo, commit


def test_build_is_deterministic_and_excludes_private_and_uncommitted_files(tmp_path, source_commit):
    repo, commit = source_commit
    first, second = tmp_path / "first.tar.gz", tmp_path / "second.tar.gz"
    receipt = bundle.build(repo, commit, first)
    assert bundle.build(repo, commit, second) == receipt
    assert first.read_bytes() == second.read_bytes()
    assert bundle.verify(
        first, expected_commit=commit, expected_sha256=receipt["archive_sha256"]
    ) == (receipt)
    with tarfile.open(first, "r:gz") as archive:
        assert set(archive.getnames()) == bundle.REQUIRED | {bundle.MANIFEST}
        assert archive.extractfile("web/index.html").read() == b"committed fixture\n"
    with pytest.raises(bundle.BundleError, match="new"):
        bundle.build(repo, commit, first)
    with pytest.raises(bundle.BundleError, match="trusted SHA-256"):
        bundle.verify(first, expected_sha256="0" * 64)


def test_release_contains_complete_allowlisted_operator_guides(tmp_path, source_commit):
    repo, _ = source_commit
    guides = bundle.OPERATOR_DOCS | bundle.OPTIONAL_ROOT_DOCS
    for name in guides:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Operator contract fixture\n", encoding="utf-8")
    bundle._git(repo, "add", "--", *sorted(guides))
    bundle._git(
        repo,
        "-c",
        "user.name=OpsArk release test",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "operator guides",
    )
    commit = bundle._git(repo, "rev-parse", "HEAD").decode().strip()
    package = tmp_path / "operator-guides.tar.gz"
    receipt = bundle.build(repo, commit, package)
    assert (
        bundle.verify(package, expected_commit=commit, expected_sha256=receipt["archive_sha256"])
        == receipt
    )
    with tarfile.open(package, "r:gz") as archive:
        assert guides.issubset(archive.getnames())
        assert "docs/PERSISTENT_CONTROL.md" not in archive.getnames()
        assert "data/access-token" not in archive.getnames()


@pytest.mark.parametrize(
    "fault",
    ["changed_content", "unsafe_path", "unlisted_entry", "private_marker", "public_address"],
)
def test_verify_rejects_tampered_archive_without_extracting(tmp_path, source_commit, fault):
    repo, commit = source_commit
    intact, bad = tmp_path / "intact.tar.gz", tmp_path / "bad.tar.gz"
    bundle.build(repo, commit, intact)
    with tarfile.open(intact, "r:gz") as source:
        rows = [(member, source.extractfile(member).read()) for member in source]
    manifest, contents = rows[0]
    if fault in {"unsafe_path", "private_marker", "public_address"}:
        value = json.loads(contents)
        member, original = rows[-1]
        if fault == "unsafe_path":
            value["files"][-1]["path"] = "../outside.js"
            member.name = "../outside.js"
        else:
            marker = b"-----BEGIN PRIVATE KEY-----" if fault == "private_marker" else b"8.8.8.8"
            changed = original + marker + b"\n"
            value["files"][-1].update(size=len(changed), sha256=bundle._sha(changed))
            member.size = len(changed)
            rows[-1] = (member, changed)
        contents = bundle._canonical(value)
        manifest.size = len(contents)
        rows[0] = (manifest, contents)
    elif fault == "changed_content":
        member, contents = rows[-1]
        rows[-1] = (member, b"!" + contents[1:])
    else:
        rows.append((tarfile.TarInfo("web/unlisted.js"), b""))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as target:
        for member, contents in rows:
            target.addfile(member, io.BytesIO(contents))
    bad.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    reason = {"private_marker": "credential marker", "public_address": "Public address"}.get(fault)
    with pytest.raises(bundle.BundleError, match=reason):
        bundle.verify(bad)
    assert not (tmp_path / "outside.js").exists()


@pytest.fixture
def runtime_copy(tmp_path, source_commit):
    repo, commit = source_commit
    archive_path = tmp_path / "source.tar.gz"
    receipt = bundle.build(repo, commit, archive_path)
    root = tmp_path / "app"
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if member.name in {"pyproject.toml", "uv.lock"} or member.name.startswith(
                ("src/", "web/")
            ):
                path = root / member.name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
    return archive_path, root, receipt


def test_runtime_rejects_stale_same_size_source_and_extra_files(runtime_copy):
    archive, root, receipt = runtime_copy
    proof = bundle.verify_runtime(
        archive,
        root,
        expected_commit=receipt["commit"],
        expected_sha256=receipt["archive_sha256"],
    )
    assert proof["runtime_file_count"] == 5 and proof["version"] == "0.17.0"
    assert len(proof["runtime_sha256"]) == 64
    source = root / "src/opsark/__init__.py"
    original = source.read_bytes()
    source.write_bytes(original.replace(b"0.17.0", b"0.18.0"))
    with pytest.raises(bundle.BundleError, match="does not match"):
        bundle.verify_runtime(archive, root)
    source.write_bytes(original)
    (root / "web/unlisted.js").touch()
    with pytest.raises(bundle.BundleError, match="unexpected source or web entry"):
        bundle.verify_runtime(archive, root)


def test_runtime_rejects_bytecode_cache_directory_and_standalone_bytecode(runtime_copy):
    archive, root, _ = runtime_copy
    cache = root / "src/opsark/__pycache__"
    cache.mkdir()
    with pytest.raises(bundle.BundleError, match="bytecode caches are not allowed"):
        bundle.verify_runtime(archive, root)
    cache.rmdir()
    (root / "src/opsark/extra.pyc").write_bytes(b"old bytecode")
    with pytest.raises(bundle.BundleError, match="bytecode caches are not allowed"):
        bundle.verify_runtime(archive, root)


def test_runtime_rejects_symlink_even_when_target_bytes_match(runtime_copy):
    archive, root, _ = runtime_copy
    source = root / "src/opsark/main.py"
    target = root / "outside.py"
    target.write_bytes(source.read_bytes())
    source.unlink()
    try:
        source.symlink_to(target)
    except OSError:
        pytest.skip("Local filesystem does not allow symbolic links")
    with pytest.raises(bundle.BundleError, match="symlinks"):
        bundle.verify_runtime(archive, root)
