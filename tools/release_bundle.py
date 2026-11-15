"""Build and check an OpsArk source bundle without using working tree contents."""

import argparse
import ast
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zlib
from pathlib import Path, PurePosixPath

MANIFEST = "release-manifest.json"
ROOT_FILES = frozenset(
    {
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".python-version",
        "Dockerfile",
        "README.md",
        "compose.yaml",
        "opsark.example.toml",
        "pyproject.toml",
        "uv.lock",
    }
)
REQUIRED = ROOT_FILES | {"src/opsark/__init__.py", "src/opsark/main.py", "web/index.html"}
OPTIONAL_ROOT_DOCS = frozenset({"CONTRIBUTING.md", "SECURITY.md", "LICENSE"})
VERSION_FILES = frozenset({"pyproject.toml", "uv.lock", "src/opsark/__init__.py"})
RUNTIME_ROOT_FILES = frozenset({"pyproject.toml", "uv.lock"})
DEPLOY_SUFFIXES = {
    "nginx": {".md", ".py"},
    "observer": {".md", ".py"},
    "readonly": {".md", ".py"},
    "security": {".md", ".py"},
    "vulnerability": {".md", ".py", ".service"},
    "web": {".md", ".py", ".conf"},
}
EXACT_DEPLOY_FILES = frozenset(
    {
        "deploy/container/README.md",
        "deploy/container/restart_action.py",
        "deploy/container/restart_journal.py",
        "deploy/container/restart_runtime.py",
        "deploy/container/restart_ssh_entry.py",
        "deploy/nginx/managed-sshd.conf",
        "deploy/nginx/managed-sudoers.conf",
        "deploy/nginx/managed-systemd.conf",
        "deploy/observer/compose.yaml",
    }
)
OPERATOR_DOCS = {
    "docs/AI_DISPATCH_ADMISSION.md",
    "docs/API_CONTRACT.md",
    "docs/COMPOSE_DISCOVERY.md",
    "docs/COMMUNITY_TRIAL.md",
    "docs/DISK_RECLAIM_EVIDENCE.md",
    "docs/AUTOMATIC_AI.md",
    "docs/AUTOMATIC_REPAIR.md",
    "docs/PLATFORM_SUPPORT.md",
    "docs/NGINX_DEPENDENCIES.md",
    "docs/RECOVERY.md",
    "docs/RELEASE_CHECK.md",
    "docs/RUNNING.md",
    "docs/SECURITY_MODEL.md",
    "docs/SECURITY_OBSERVATION.md",
    "docs/SEALED_BACKUP.md",
    "docs/SERVICE_ACTIVATION.md",
    "docs/VULNERABILITY_AI.md",
    "docs/VULNERABILITY_EVIDENCE.md",
    "docs/VULNERABILITY_REMEDIATION.md",
    "docs/VULNERABILITY_WATCH.md",
    "docs/WEB_SECURITY_OBSERVATION.md",
}
TOOL_FILES = {
    "tools/_sealed_archive.py",
    "tools/_sealed_defense.py",
    "tools/_sealed_paths.py",
    "tools/release_bundle.py",
    "tools/sealed_backup.py",
    "tools/verify_activation_evidence.py",
    "tools/verify_evidence.py",
}
MAX_FILES = 512
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_CONTENT_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_CONTENT_BYTES + 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SEGMENT = re.compile(r"[A-Za-z0-9_@-][A-Za-z0-9_.@-]*")
_WINDOWS_DEVICE = re.compile(r"(?:aux|con|nul|prn|com[1-9]|lpt[1-9])")
_VERSION = re.compile(r"[0-9][A-Za-z0-9.+!-]{0,63}")
_ADDRESS = re.compile(
    rb"(?<![.\w])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![.\w])"
    rb"|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
)
_PRIVATE_MARKER = re.compile(
    rb"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
    rb"|gh[pousr]_[A-Za-z0-9]{32,}|github_pat_[A-Za-z0-9_]{30,}"
    rb"|sk-(?:proj-|ant-api[0-9]+-)?[A-Za-z0-9_-]{32,}|AKIA[A-Z0-9]{16}"
    rb"|(?i:[a-z]:[\\/]+(?:users|opsark)[\\/]+|/(?:home/[^/\s'\"]+|root)/\.ssh/)"
)
_PRIVATE_SEGMENTS = {
    "__pycache__",
    "access-token",
    "credentials",
    "data",
    "known_hosts",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "private",
    "secrets",
}


class BundleError(ValueError):
    """The source commit or bundle violates the release contract."""


def _allowed(name: str) -> bool:
    if name in ROOT_FILES or name in OPTIONAL_ROOT_DOCS:
        return True
    parts = name.split("/")
    if len(name) > 100:
        return False
    for part in parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            not _SEGMENT.fullmatch(part)
            or part.endswith(".")
            or stem in _PRIVATE_SEGMENTS
            or _WINDOWS_DEVICE.fullmatch(stem)
        ):
            return False
    path = PurePosixPath(name)
    if parts[:2] == ["src", "opsark"] and len(parts) >= 3:
        return path.suffix == ".py" or (parts[2] == "fixtures" and path.suffix == ".json")
    if len(parts) == 2:
        if parts[0] == "web":
            return path.suffix in {".html", ".css", ".js"}
        return name in OPERATOR_DOCS or name in TOOL_FILES
    if len(parts) == 3 and parts[0] == "deploy":
        return name in EXACT_DEPLOY_FILES or path.suffix in DEPLOY_SUFFIXES.get(parts[1], ())
    return False


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_content(name: str, data: bytes) -> None:
    if _PRIVATE_MARKER.search(data):
        raise BundleError(f"Private path or credential marker in source file: {name}")
    for match in _ADDRESS.finditer(data):
        try:
            address = ipaddress.ip_address(match[0].decode())
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            raise BundleError(f"Public address literal in source file: {name}")


def _canonical(value: dict) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def _git(repo: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise BundleError("Git is required to build a source bundle")
    result = subprocess.run(  # noqa: S603 - argument vector only; no shell
        [executable, "--no-replace-objects", "-C", str(repo), *arguments],
        input=input_data,
        capture_output=True,
        timeout=40,
        check=False,
    )
    if result.returncode:
        raise BundleError("Unable to read the specified Git commit")
    return result.stdout


def _source_files(repo: Path, commit: str) -> list[tuple[str, int, bytes]]:
    if not _COMMIT.fullmatch(commit):
        raise BundleError("Use the full lowercase Git commit ID")
    if _git(repo, "rev-parse", "--verify", commit + "^{commit}").strip() != commit.encode():
        raise BundleError("The ID must identify a commit directly")
    tree = _git(repo, "ls-tree", "-rlz", "--full-tree", commit)
    selected = []
    total = 0
    for line in tree.split(b"\0"):
        if not line:
            continue
        metadata, encoded_name = line.split(b"\t", 1)
        if not encoded_name.isascii():
            continue
        name = encoded_name.decode()
        if not _allowed(name):
            continue
        mode, kind, oid, size = metadata.split()
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise BundleError("An allowed source path is not a regular Git blob")
        size = int(size)
        total += size
        if not 0 <= size <= MAX_FILE_BYTES or total > MAX_CONTENT_BYTES:
            raise BundleError("Committed sources exceed the bundle size budget")
        selected.append((name, int(mode, 8) & 0o777, oid, size))
        if len(selected) > MAX_FILES:
            raise BundleError("Committed sources exceed the bundle file budget")
    if not REQUIRED.issubset(name for name, _, _, _ in selected):
        raise BundleError("The specified commit is missing required OpsArk source files")
    selected.sort(key=lambda row: row[0])
    git_input = b"".join(oid + b"\n" for _, _, oid, _ in selected)
    objects = io.BytesIO(_git(repo, "cat-file", "--batch", input_data=git_input))
    result = []
    for name, mode, oid, size in selected:
        if objects.readline() != oid + b" blob " + str(size).encode() + b"\n":
            raise BundleError("Git did not return the expected source blob")
        data = objects.read(size)
        if len(data) != size or objects.read(1) != b"\n":
            raise BundleError("Git source blob was truncated")
        _check_content(name, data)
        result.append((name, mode, data))
    if objects.read(1):
        raise BundleError("Git returned unexpected source data")
    return result


def _project_version(files: dict[str, bytes]) -> str:
    try:
        project = tomllib.loads(files["pyproject.toml"].decode())["project"]
        version = project["version"]
        if project["name"] != "ops-ark" or not isinstance(version, str):
            raise ValueError
        locked = tomllib.loads(files["uv.lock"].decode())["package"]
        local = [
            row["version"]
            for row in locked
            if row.get("name") == "ops-ark" and row.get("source") == {"virtual": "."}
        ]
        runtime = [
            node.value.value
            for node in ast.parse(files["src/opsark/__init__.py"]).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
        ]
        if not _VERSION.fullmatch(version) or local != [version] or runtime != [version]:
            raise ValueError
        return version
    except (AttributeError, KeyError, SyntaxError, TypeError, ValueError) as error:
        raise BundleError("Project, lockfile and runtime versions do not agree") from error


def _member(name: str, mode: int, size: int) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.mode = mode
    member.size = size
    return member


def _read_content(stream: gzip.GzipFile, size: int) -> bytes:
    content = stream.read(size)
    padding = (-size) % tarfile.BLOCKSIZE
    if len(content) != size or stream.read(padding) != bytes(padding):
        raise BundleError("Archive content is truncated or contains invalid padding")
    return content


def _read_manifest(stream: gzip.GzipFile) -> tuple[dict, int]:
    header = stream.read(tarfile.BLOCKSIZE)
    member = tarfile.TarInfo.frombuf(header, "ascii", "strict")
    if not 1 <= member.size <= MAX_MANIFEST_BYTES or header != _member(
        MANIFEST, 0o644, member.size
    ).tobuf(format=tarfile.USTAR_FORMAT):
        raise BundleError("Invalid release manifest member")
    raw = _read_content(stream, member.size)
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "commit", "version", "files"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["commit"], str)
        or not _COMMIT.fullmatch(value["commit"])
        or not isinstance(value["version"], str)
        or not _VERSION.fullmatch(value["version"])
        or not isinstance(value["files"], list)
        or not 1 <= len(value["files"]) <= MAX_FILES
        or _canonical(value) != raw
    ):
        raise BundleError("Invalid release manifest")
    return value, tarfile.BLOCKSIZE + member.size + (-member.size) % tarfile.BLOCKSIZE


def _check_archive(compressed: bytes) -> tuple[dict, list[dict]]:
    total = 0
    names: set[str] = set()
    directories: set[str] = set()
    previous = ""
    versions: dict[str, bytes] = {}
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
        manifest, position = _read_manifest(stream)
        for entry in manifest["files"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "size", "mode", "sha256"}:
                raise BundleError("Invalid release file manifest row")
            name, size, mode, digest = (entry[key] for key in ("path", "size", "mode", "sha256"))
            if (
                not isinstance(name, str)
                or not _allowed(name)
                or name <= previous
                or name.casefold() in names
                or type(mode) is not int
                or mode not in {0o644, 0o755}
                or type(size) is not int
                or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest)
            ):
                raise BundleError("Invalid, duplicate or unexpected release path")
            previous = name
            folded_name = name.casefold()
            parents = {str(parent).casefold() for parent in PurePosixPath(name).parents}
            if folded_name in directories or parents & names:
                raise BundleError("Archive contains conflicting file and directory paths")
            names.add(folded_name)
            directories.update(parents)
            total += size
            if total > MAX_CONTENT_BYTES:
                raise BundleError("Archive exceeds the uncompressed size budget")
            header = stream.read(tarfile.BLOCKSIZE)
            if header != _member(name, mode, size).tobuf(format=tarfile.USTAR_FORMAT):
                raise BundleError("Archive entry does not match the release manifest")
            content = _read_content(stream, size)
            if _sha(content) != digest:
                raise BundleError("Archive entry SHA-256 does not match the release manifest")
            _check_content(name, content)
            position += tarfile.BLOCKSIZE + size + (-size) % tarfile.BLOCKSIZE
            if name in VERSION_FILES:
                versions[name] = content
        trailer = 2 * tarfile.BLOCKSIZE
        trailer += (-(position + trailer)) % tarfile.RECORDSIZE
        if stream.read(trailer) != bytes(trailer) or stream.read(1):
            raise BundleError("Archive contains unexpected trailing data")
    if not names.issuperset(name.casefold() for name in REQUIRED):
        raise BundleError("Archive is missing required OpsArk source files")
    if _project_version(versions) != manifest["version"]:
        raise BundleError("Release manifest version does not match the source")
    return (
        {
            "commit": manifest["commit"],
            "version": manifest["version"],
            "file_count": len(names),
            "archive_sha256": _sha(compressed),
        },
        manifest["files"],
    )


def _open_read(path: Path):
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    return os.fdopen(os.open(path, flags), "rb")


def _verified_archive(
    archive: Path, expected_commit: str | None, expected_sha256: str | None
) -> tuple[dict, list[dict]]:
    if expected_commit is not None and not _COMMIT.fullmatch(expected_commit):
        raise BundleError("Invalid expected commit ID")
    if expected_sha256 is not None and not _SHA256.fullmatch(expected_sha256):
        raise BundleError("Invalid expected SHA-256")
    if not stat.S_ISREG(archive.lstat().st_mode):
        raise BundleError("Archive must be a regular file")
    with _open_read(archive) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_ARCHIVE_BYTES:
            raise BundleError("Archive exceeds the compressed size budget")
        compressed = source.read(MAX_ARCHIVE_BYTES + 1)
        if len(compressed) != info.st_size:
            raise BundleError("Archive changed while it was read")
    if expected_sha256 is not None and _sha(compressed) != expected_sha256:
        raise BundleError("Archive does not match the trusted SHA-256")
    result, files = _check_archive(compressed)
    if expected_commit is not None and result["commit"] != expected_commit:
        raise BundleError("Archive does not identify the expected commit")
    return result, files


def verify(
    archive: Path, *, expected_commit: str | None = None, expected_sha256: str | None = None
) -> dict:
    """Check a bundle in memory and return its verified metadata without extraction."""
    result, _ = _verified_archive(archive, expected_commit, expected_sha256)
    return result


def _runtime_path(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise BundleError("Runtime is missing a required entry") from error
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise BundleError("Runtime symlinks and junctions are not allowed")
    return info


def _runtime_file(path: Path, entry: dict) -> None:
    name, size, digest = (entry[key] for key in ("path", "size", "sha256"))
    info = _runtime_path(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size != size:
        raise BundleError(f"Runtime file does not match the release manifest: {name}")
    with _open_read(path) as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise BundleError(f"Runtime file changed while it was opened: {name}")
        data = source.read(size + 1)
        if len(data) != size or _sha(data) != digest:
            raise BundleError(f"Runtime file does not match the release manifest: {name}")


def _runtime_tree(root: Path, expected: dict[str, dict]) -> set[str]:
    folders = {str(folder) for name in expected for folder in PurePosixPath(name).parents}
    found = set()
    pending = [root / "src", root / "web"]
    while pending:
        folder = pending.pop()
        if not stat.S_ISDIR(_runtime_path(folder).st_mode):
            raise BundleError("Runtime source and web roots must be directories")
        for child in folder.iterdir():
            info = _runtime_path(child)
            name = child.relative_to(root).as_posix()
            if child.name.casefold() == "__pycache__" or child.suffix.casefold() == ".pyc":
                raise BundleError("Runtime source and web bytecode caches are not allowed")
            if name in expected:
                _runtime_file(child, expected[name])
                found.add(name)
            elif name in folders and stat.S_ISDIR(info.st_mode):
                pending.append(child)
            else:
                raise BundleError("Runtime contains an unexpected source or web entry")
    return found


def verify_runtime(
    archive: Path,
    root: Path,
    *,
    expected_commit: str | None = None,
    expected_sha256: str | None = None,
) -> dict:
    """Match an inert image or directory's runtime files against a verified source bundle."""
    result, files = _verified_archive(archive, expected_commit, expected_sha256)
    if (
        not stat.S_ISDIR(_runtime_path(root).st_mode)
        or root.resolve(strict=True) != root.absolute()
    ):
        raise BundleError("Runtime root must be a real directory path")
    expected = {
        row["path"]: row
        for row in files
        if row["path"] in RUNTIME_ROOT_FILES or row["path"].startswith(("src/", "web/"))
    }
    for name in RUNTIME_ROOT_FILES:
        _runtime_file(root / name, expected[name])
    if (_runtime_tree(root, expected) | RUNTIME_ROOT_FILES) != expected.keys():
        raise BundleError("Runtime is missing a source or web file")
    runtime_content = [
        {key: row[key] for key in ("path", "size", "sha256")} for row in expected.values()
    ]
    return {
        "commit": result["commit"],
        "version": result["version"],
        "archive_sha256": result["archive_sha256"],
        "runtime_file_count": len(expected),
        "runtime_sha256": _sha(_canonical({"files": runtime_content})),
    }


def build(repo: Path, commit: str, output: Path) -> dict:
    """Build from committed Git objects and install a verified bundle at a new path."""
    if not output.name.endswith(".tar.gz") or output.exists() or output.is_symlink():
        raise BundleError("Choose a new .tar.gz output file")
    files = _source_files(repo, commit)
    version = _project_version({name: data for name, _, data in files if name in VERSION_FILES})
    manifest = _canonical(
        {
            "schema_version": 1,
            "commit": commit,
            "version": version,
            "files": [
                {"path": name, "mode": mode, "size": len(data), "sha256": _sha(data)}
                for name, mode, data in files
            ],
        }
    )
    with tempfile.TemporaryDirectory(prefix=".opsark-release-", dir=output.parent) as directory:
        staged = Path(directory) / "source.tar.gz"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(staged, flags, 0o600), "wb") as destination:
            with (
                gzip.GzipFile(
                    fileobj=destination, mode="wb", filename="", mtime=0, compresslevel=9
                ) as compressed,
                tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
            ):
                archive.addfile(_member(MANIFEST, 0o644, len(manifest)), io.BytesIO(manifest))
                for name, mode, data in files:
                    archive.addfile(_member(name, mode, len(data)), io.BytesIO(data))
            destination.flush()
            os.fsync(destination.fileno())
        result = verify(staged, expected_commit=commit)
        os.link(staged, output)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    create = commands.add_parser("build")
    create.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    create.add_argument("--commit", required=True)
    create.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("verify")
    runtime = commands.add_parser("verify-runtime")
    for command in (check, runtime):
        command.add_argument("archive", type=Path)
        command.add_argument("--expected-commit")
        command.add_argument("--expected-sha256")
    runtime.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "build":
            result = build(args.repo, args.commit, args.output)
        elif args.operation == "verify-runtime":
            result = verify_runtime(
                args.archive,
                args.root,
                expected_commit=args.expected_commit,
                expected_sha256=args.expected_sha256,
            )
        else:
            result = verify(
                args.archive,
                expected_commit=args.expected_commit,
                expected_sha256=args.expected_sha256,
            )
    except BundleError as error:
        parser.exit(1, f"Release bundle rejected: {error}\n")
    except (
        EOFError,
        OSError,
        RecursionError,
        ValueError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zlib.error,
    ):
        parser.exit(
            1, "Release bundle rejected: unreadable or invalid archive, runtime or Git source\n"
        )
    print(_canonical(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
