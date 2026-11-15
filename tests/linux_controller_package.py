"""Build an inert, complete Linux test source closure from one committed Git tree.

Only committed public sources are read. Working-tree changes, local data and
credentials never enter either package. The normal release contract is unchanged.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

MAX_FILES = 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_CONTENT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_CONTENT_BYTES + 2 * 1024 * 1024
MAX_IDENTITY_BYTES = 512 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SEGMENT = re.compile(r"[A-Za-z0-9_@-][A-Za-z0-9_.@-]*\Z")
DEVICE = re.compile(r"(?:aux|con|nul|prn|com[1-9]|lpt[1-9])\Z", re.I)
PRIVATE = frozenset(
    {"data", "secrets", "credentials", "private", "__pycache__", "known_hosts", "access-token"}
)
SUFFIXES = frozenset({".py", ".md", ".sh", ".conf", ".yaml", ".yml", ".json", ".service"})
ROOT_SOURCE_FILES = frozenset(
    {
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".python-version",
        "CONTRIBUTING.md",
        "Dockerfile",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "compose.yaml",
        "opsark.example.toml",
        "pyproject.toml",
        "uv.lock",
    }
)
KEY_BLOCK = re.compile(
    rb"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]{20,}\r?\n)+-----END "
)

# These exact committed tests intentionally exercise credential/path/address
# rejection. A changed file must be reviewed again, never accepted by its label.
SYNTHETIC_EXCEPTIONS = {
    "tests/test_nginx_dependencies.py": (
        "1590afb014ef81ac1c2bd42cb4e8320f17fbe5bccf8b75a4f11c6397726a5ab0"
    ),
    "tests/ssh_defense_binding_loss_lab.py": (
        "33812d5de6b379a6aef727af1898a614ae9681999bed1c8df3597ac58ea63639"
    ),
    "tests/ssh_defense_transport_lab.py": (
        "9e42aa250d3a8f2e177ad25b22b0e1fd5e4d2ad3ac989547524d492de4277c7d"
    ),
    "tests/ai_compat_contract_server.py": (
        "0c6ff5b6c056a7042b79e786b0f0d523c3ad203ff4197a086d4f4b488ad6f5ea"
    ),
    "tests/browser_defense_native_smoke.py": (
        "af6891ff962d77d5ad5d54c455a2fe0d69b7bc993ef4d278e41ee09659939306"
    ),
    "tests/lab/entrypoint.sh": ("5925a796c436521e13464441b4570fda6b5f2c2a4b932aae9871f5970e76dc11"),
    "tests/test_ai_egress.py": ("6b484aac1b5b3c7bb5009f5b540e417189058b7b9c92951d75df9544fe96c178"),
    "tests/test_ai_egress_release_matrix.py": (
        "3d6c88a1ca615717571ce3b4670f22ed475230554e0f179f90fa0f5b622712f3"
    ),
    "tests/test_ai_egress_ssh_entry_matrix.py": (
        "91a4b5068acd3c938dd1f5201a314b67a3896de623e730a8530bc0e8d3e7ff83"
    ),
    "tests/test_defense_business_lab.py": (
        "30b2cf6428ff7ee47901e236a38fbd9f65ebf59396f9de783c4a6258734280c4"
    ),
    "tests/test_defense_requests.py": (
        "6d66889773f0992ca02882f0729c27f5ef4dfebd5d6b4a90ae0fec8f830285f8"
    ),
    "tests/test_defense_task_watch_native_driver.py": (
        "55ce78388df2dec55b3994901fe40d4a9737beae22a6e9f390704ea8a7aba1c6"
    ),
    "tests/test_host_onboarding.py": (
        "63860c674bf70fd55fe63a8b7e03b5a3b601acbd7ce4ebb8d014c93319f24f4f"
    ),
    "tests/test_linux_controller_package.py": (
        "f99adf9ba6335ca6ddb03f91945dccd8524734dac6a71f7ffbc9997d0925d1b9"
    ),
    "tests/test_redaction.py": ("1cf024567debdc1765204b35b8440c5bd50dc97358ee4d5b14b691b175142dfb"),
    "tests/test_release_bundle.py": (
        "0209b164eceb2858cce6c13971a68cd95ecdde7d36d386c3e5d3627e79979804"
    ),
    "tests/test_sealed_defense.py": (
        "ab1c2103ca16b6c3fe728a36a1eac5fda28b9eb0998b300c484170d7a02f589c"
    ),
    "tests/test_ssh_fixture_evidence.py": (
        "db0115763751806634a4d2f13e2f9f58c2067d701bfbaa22cdb2cd0a15511962"
    ),
    "tests/test_ssh_fixture_executor.py": (
        "f25dedfc0816eea0d7c0dcb29e583c3f81ca7a1ad7921156e39d01973f7023bd"
    ),
    "tests/test_vulnerability_evidence.py": (
        "c902260b099db7b24d0f798d7a9b7d0fd2cfe69b6d83fc2680ee1762ffb57c2c"
    ),
}


class PackageError(ValueError):
    """Only bounded public phase codes escape a source validation failure."""


def require(value, code):
    if not value:
        raise PackageError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def _git(repo, *arguments, input_data=None):
    executable = shutil.which("git")
    if executable is None:
        raise PackageError("git_missing")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    result = subprocess.run(  # noqa: S603 -- fixed Git arguments, no shell or network.
        [
            executable,
            "--no-replace-objects",
            "-C",
            str(repo),
            "-c",
            "core.autocrlf=false",
            "-c",
            "tar.umask=0022",
            *arguments,
        ],
        input=input_data,
        capture_output=True,
        check=False,
        timeout=60,
        env=environment,
    )
    require(result.returncode == 0, "git_source_unavailable")
    return result.stdout


def _release_tool(path):
    require(path.is_file() and not path.is_symlink(), "release_tool_missing")
    spec = importlib.util.spec_from_file_location("opsark_linux_release_tool", path)
    if spec is None or spec.loader is None:
        raise PackageError("release_tool_missing")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _name(name, release=None):
    require(type(name) is str and 0 < len(name) <= 160, "source_path_invalid")
    if name in ROOT_SOURCE_FILES:
        return True
    parts = name.split("/")
    require(
        not name.startswith("/")
        and all(
            SEGMENT.fullmatch(part)
            and not part.endswith(".")
            and part.split(".", 1)[0].casefold() not in PRIVATE
            and not DEVICE.fullmatch(part.split(".", 1)[0])
            and not part.casefold().startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
            for part in parts
        ),
        "source_path_invalid",
    )
    if release is not None and release._allowed(name):
        return True
    if parts[:2] == ["src", "opsark"] and len(parts) >= 3:
        return PurePosixPath(name).suffix == ".py" or (
            parts[2] == "fixtures" and PurePosixPath(name).suffix == ".json"
        )
    if len(parts) == 2 and parts[0] in {"web", "docs"}:
        return PurePosixPath(name).suffix in (
            {".html", ".css", ".js"} if parts[0] == "web" else {".md"}
        )
    return (
        len(parts) >= 2
        and parts[0] in {"tests", "deploy", "tools"}
        and (PurePosixPath(name).suffix in SUFFIXES or parts[-1] in {"Dockerfile", "sshd_config"})
    )


def _manifest_identity(identity):
    require(
        type(identity) is dict
        and set(identity)
        == {
            "schema_version",
            "kind",
            "commit",
            "source_archive_sha256",
            "source_archive_bytes",
            "candidate_archive_sha256",
            "candidate_archive_bytes",
            "content_bytes",
            "files",
        },
        "identity_shape_invalid",
    )
    require(
        identity["schema_version"] == 1
        and type(identity["schema_version"]) is int
        and identity["kind"] == "opsark-linux-controller-source/v1",
        "identity_shape_invalid",
    )
    require(
        type(identity["commit"]) is str and COMMIT.fullmatch(identity["commit"]), "commit_invalid"
    )
    for key in ("source_archive_sha256", "candidate_archive_sha256"):
        require(
            type(identity[key]) is str and SHA256.fullmatch(identity[key]),
            "identity_digest_invalid",
        )
    for key in ("source_archive_bytes", "candidate_archive_bytes", "content_bytes"):
        require(
            type(identity[key]) is int and 0 < identity[key] <= MAX_ARCHIVE_BYTES,
            "identity_size_invalid",
        )
    files = identity["files"]
    require(type(files) is list and 0 < len(files) <= MAX_FILES, "identity_files_invalid")
    seen, total = set(), 0
    for entry in files:
        require(
            type(entry) is dict and set(entry) == {"path", "mode", "size", "sha256"},
            "identity_entry_invalid",
        )
        name = entry["path"]
        # Root dotfiles are fixed separately, never a wildcard for hidden files.
        require(_name(name), "identity_path_invalid")
        require(type(name) is str and name not in seen, "identity_duplicate_path")
        require(
            type(entry["mode"]) is int and entry["mode"] in {0o644, 0o755}, "identity_mode_invalid"
        )
        require(
            type(entry["size"]) is int and 0 <= entry["size"] <= MAX_FILE_BYTES,
            "identity_size_invalid",
        )
        require(
            type(entry["sha256"]) is str and SHA256.fullmatch(entry["sha256"]),
            "identity_digest_invalid",
        )
        total += entry["size"]
        seen.add(name)
    require(files == sorted(files, key=lambda entry: entry["path"]), "identity_order_invalid")
    require(
        total == identity["content_bytes"] and total <= MAX_CONTENT_BYTES, "identity_size_invalid"
    )
    require(
        {
            "pyproject.toml",
            "uv.lock",
            "tools/release_bundle.py",
            "src/opsark/main.py",
            "web/index.html",
        }.issubset(seen)
        and any(name.startswith("tests/") for name in seen),
        "identity_required_missing",
    )
    return files


def read_identity(path):
    data = _read(path, MAX_IDENTITY_BYTES)
    identity = json.loads(data)
    _manifest_identity(identity)
    require(canonical(identity) == data, "identity_encoding_invalid")
    return identity


def _read(path, limit):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "input_file_invalid")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "input_file_oversize")
    return data


def _archive_entries(raw, commit, files):
    expected = {entry["path"]: entry for entry in files}
    parents = {
        str(parent)
        for name in expected
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    seen, directories = set(), set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        require(archive.pax_headers == {"comment": commit}, "source_commit_comment_invalid")
        for member in archive:
            require(member.pax_headers == {"comment": commit}, "source_pax_invalid")
            name = member.name.rstrip("/") if member.isdir() else member.name
            if member.isdir():
                require(
                    name in parents and name not in directories and member.mode == 0o755,
                    "source_directory_invalid",
                )
                directories.add(name)
                continue
            require(
                member.isfile() and name in expected and name not in seen, "source_member_invalid"
            )
            entry = expected[name]
            require(
                member.mode == entry["mode"] and member.size == entry["size"],
                "source_metadata_invalid",
            )
            stream = archive.extractfile(member)
            if stream is None:
                raise PackageError("source_member_unreadable")
            data = stream.read(MAX_FILE_BYTES + 1)
            require(
                len(data) == member.size and sha(data) == entry["sha256"], "source_digest_invalid"
            )
            seen.add(name)
        end = archive.offset
    require(
        len(raw) % 512 == 0 and len(raw) - end >= 1024 and not raw[end:].strip(b"\0"),
        "source_trailing_data_invalid",
    )
    require(seen == set(expected), "source_members_missing")


def verify_package(archive_path, identity):
    files = _manifest_identity(identity)
    compressed = _read(archive_path, MAX_ARCHIVE_BYTES)
    require(
        len(compressed) == identity["source_archive_bytes"]
        and sha(compressed) == identity["source_archive_sha256"],
        "source_archive_digest_invalid",
    )
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(MAX_ARCHIVE_BYTES + 1)
        require(len(raw) <= MAX_ARCHIVE_BYTES and not stream.read(1), "source_archive_oversize")
    _archive_entries(raw, identity["commit"], files)
    return {
        "commit": identity["commit"],
        "files": len(files),
        "content_bytes": identity["content_bytes"],
        "source_archive_sha256": identity["source_archive_sha256"],
    }


def verify_source_tree(root, identity):
    files = _manifest_identity(identity)
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "source_root_invalid")
    expected = {entry["path"]: entry for entry in files}
    parents = {
        str(parent)
        for name in expected
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    seen = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "source_tree_link_refused")
        if path.is_dir():
            require(path.relative_to(root).as_posix() in parents, "source_tree_extra_directory")
            continue
        require(path.is_file(), "source_tree_type_invalid")
        name = path.relative_to(root).as_posix()
        require(name in expected, "source_tree_extra_file")
        entry = expected[name]
        data = _read(path, MAX_FILE_BYTES)
        require(
            len(data) == entry["size"] and sha(data) == entry["sha256"],
            "source_tree_digest_invalid",
        )
        if os.name != "nt":
            require(stat.S_IMODE(path.stat().st_mode) == entry["mode"], "source_tree_mode_invalid")
        seen.add(name)
    require(seen == set(expected), "source_tree_file_missing")
    return {
        "commit": identity["commit"],
        "files": len(files),
        "source_tree_sha256": sha(canonical(files)),
    }


def verify_candidate(candidate, source_root, identity):
    verify_source_tree(source_root, identity)
    require(
        len(_read(candidate, MAX_ARCHIVE_BYTES)) == identity["candidate_archive_bytes"],
        "candidate_size_invalid",
    )
    tool = _release_tool(Path(source_root) / "tools/release_bundle.py")
    return tool.verify_runtime(
        Path(candidate),
        Path(source_root),
        expected_commit=identity["commit"],
        expected_sha256=identity["candidate_archive_sha256"],
    )


def build(repo, commit, output_dir):
    repo, output_dir = Path(repo).resolve(), Path(output_dir)
    require(type(commit) is str and COMMIT.fullmatch(commit), "commit_invalid")
    require(
        output_dir.is_absolute()
        and output_dir.parent.is_dir()
        and not output_dir.exists()
        and not output_dir.is_symlink(),
        "output_not_fresh",
    )
    require(
        _git(repo, "rev-parse", "--verify", commit + "^{commit}").strip() == commit.encode(),
        "commit_invalid",
    )
    tool_bytes = _git(repo, "show", commit + ":tools/release_bundle.py")
    require(len(tool_bytes) <= MAX_FILE_BYTES, "release_tool_oversize")
    with tempfile.TemporaryDirectory(
        prefix=".opsark-linux-package-", dir=output_dir.parent
    ) as temporary:
        stage = Path(temporary)
        tool_path = stage / "release_bundle.py"
        tool_path.write_bytes(tool_bytes)
        tool = _release_tool(tool_path)
        selected, total = [], 0
        for row in _git(repo, "ls-tree", "-rlz", "--full-tree", commit).split(b"\0"):
            if not row:
                continue
            metadata, encoded_name = row.split(b"\t", 1)
            require(encoded_name.isascii(), "non_ascii_git_path")
            name = encoded_name.decode("ascii")
            controlled = name.split("/", 1)[0] in {"tests", "deploy", "tools", "src", "web"}
            if not controlled and not tool._allowed(name):
                continue  # Never read an excluded local/private Git blob.
            require(_name(name, tool), "source_path_not_allowed")
            mode, kind, oid, size = metadata.split()
            require(kind == b"blob" and mode in {b"100644", b"100755"}, "source_not_regular_blob")
            size = int(size)
            total += size
            require(size <= MAX_FILE_BYTES and total <= MAX_CONTENT_BYTES, "source_size_budget")
            selected.append((name, int(mode, 8) & 0o777, oid, size))
            require(len(selected) <= MAX_FILES, "source_file_budget")
        selected.sort()
        objects = io.BytesIO(
            _git(
                repo, "cat-file", "--batch", input_data=b"".join(row[2] + b"\n" for row in selected)
            )
        )
        files = []
        for name, mode, oid, size in selected:
            require(
                objects.readline() == oid + b" blob " + str(size).encode() + b"\n",
                "git_blob_header_invalid",
            )
            data = objects.read(size)
            require(len(data) == size and objects.read(1) == b"\n", "git_blob_truncated")
            require(not KEY_BLOCK.search(data), "private_key_block_refused")
            try:
                tool._check_content(name, data)
            except tool.BundleError:
                require(
                    SYNTHETIC_EXCEPTIONS.get(name) == sha(data), "unreviewed_private_source_marker"
                )
            files.append({"path": name, "mode": mode, "size": size, "sha256": sha(data)})
        require(not objects.read(1), "git_blob_trailing_data")
        require(tool.REQUIRED.issubset(entry["path"] for entry in files), "required_source_missing")
        prefixes = {"src", "web", "tests", "deploy", "tools"}
        paths = sorted(
            {
                entry["path"].split("/", 1)[0]
                if entry["path"].split("/", 1)[0] in prefixes
                else entry["path"]
                for entry in files
            }
        )
        raw = _git(repo, "archive", "--format=tar", commit, "--", *paths)
        require(len(raw) <= MAX_ARCHIVE_BYTES, "source_archive_oversize")
        _archive_entries(raw, commit, files)
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        require(len(compressed) <= MAX_ARCHIVE_BYTES, "source_archive_oversize")
        candidate_path = stage / "candidate.tar.gz"
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        result = subprocess.run(  # noqa: S603 -- committed official release tool, fixed local args.
            [
                sys.executable,
                "-I",
                "-B",
                str(tool_path),
                "build",
                "--repo",
                str(repo),
                "--commit",
                commit,
                "--output",
                str(candidate_path),
            ],
            capture_output=True,
            timeout=90,
            check=False,
            env=environment,
        )
        require(result.returncode == 0, "official_candidate_build_refused")
        receipt = json.loads(result.stdout)
        candidate = _read(candidate_path, MAX_ARCHIVE_BYTES)
        require(
            receipt["commit"] == commit and receipt["archive_sha256"] == sha(candidate),
            "candidate_receipt_invalid",
        )
        identity = {
            "schema_version": 1,
            "kind": "opsark-linux-controller-source/v1",
            "commit": commit,
            "source_archive_sha256": sha(compressed),
            "source_archive_bytes": len(compressed),
            "candidate_archive_sha256": sha(candidate),
            "candidate_archive_bytes": len(candidate),
            "content_bytes": total,
            "files": files,
        }
        _manifest_identity(identity)
        identity_bytes = canonical(identity)
        require(len(identity_bytes) <= MAX_IDENTITY_BYTES, "identity_oversize")
        output_dir.mkdir(mode=0o700)
        for name, data in (
            ("source.tar.gz", compressed),
            ("candidate.tar.gz", candidate),
            ("identity.json", identity_bytes),
        ):
            with (output_dir / name).open("xb") as destination:
                destination.write(data)
        verify_package(output_dir / "source.tar.gz", identity)
        return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        identity = build(args.repo, args.commit, args.output)
        print(
            json.dumps(
                {key: value for key, value in identity.items() if key != "files"}, sort_keys=True
            )
        )
        return 0
    except (PackageError, OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        print("Linux source package refused; no deployment was activated.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
