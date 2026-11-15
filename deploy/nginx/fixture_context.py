"""Seal the closed, static dependency graph of the isolated Nginx fixture."""

import base64
import binascii
import errno
import json
import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from deploy.nginx import config_snapshot

RUNTIME_MOUNT = "/fixture-runtime"
TLS_MOUNT = "/fixture-tls"
FIXTURE_FILES = MappingProxyType(
    {
        "nginx.conf": b"""daemon off;
master_process on;
worker_processes 1;
pid /run/opsark-nginx-live/nginx.pid;
error_log stderr crit;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path /run/opsark-nginx-live/body;
    proxy_temp_path /run/opsark-nginx-live/proxy;
    fastcgi_temp_path /run/opsark-nginx-live/fastcgi;
    uwsgi_temp_path /run/opsark-nginx-live/uwsgi;
    scgi_temp_path /run/opsark-nginx-live/scgi;
    include /fixture-runtime/includes/sites.conf;
}
""",
        "includes/sites.conf": b"""include /fixture-runtime/sites/default.conf;
include /fixture-runtime/sites/control.conf;
include /fixture-sites/opsark-isolated-restore-fixture.conf;
""",
        "sites/default.conf": b"""server {
    listen 127.0.0.1:18087 default_server;
    server_name _;
    return 404;
}
""",
        "sites/control.conf": b"""server {
    listen 127.0.0.1:18087;
    server_name control.opsark.invalid;
    location = /healthz { default_type text/plain; return 200 "opsark-control"; }
}
""",
    }
)
TLS_FIXTURE_FILES = MappingProxyType(
    {
        **FIXTURE_FILES,
        "nginx.conf": FIXTURE_FILES["nginx.conf"].replace(
            b"    access_log off;\n",
            b"    access_log off;\n"
            b"    ssl_certificate /fixture-tls/cert.pem;\n"
            b"    ssl_certificate_key /fixture-tls/key.pem;\n"
            b"    ssl_protocols TLSv1.2 TLSv1.3;\n",
        ),
        "sites/default.conf": FIXTURE_FILES["sites/default.conf"].replace(
            b"18087 default_server", b"18087 ssl default_server"
        ),
        "sites/control.conf": FIXTURE_FILES["sites/control.conf"].replace(b"18087;", b"18087 ssl;"),
    }
)
CHAIN_FIXTURE_FILES = MappingProxyType(
    {
        **TLS_FIXTURE_FILES,
        "nginx.conf": TLS_FIXTURE_FILES["nginx.conf"]
        .replace(b"/fixture-tls/cert.pem", b"/fixture-tls/target-chain.pem")
        .replace(b"/fixture-tls/key.pem", b"/fixture-tls/target-key.pem"),
        "sites/default.conf": TLS_FIXTURE_FILES["sites/default.conf"].replace(
            b"    server_name _;\n",
            b"    server_name _;\n"
            b"    ssl_certificate /fixture-tls/default-chain.pem;\n"
            b"    ssl_certificate_key /fixture-tls/default-key.pem;\n",
        ),
        "sites/control.conf": TLS_FIXTURE_FILES["sites/control.conf"].replace(
            b"    server_name control.opsark.invalid;\n",
            b"    server_name control.opsark.invalid;\n"
            b"    ssl_certificate /fixture-tls/control-chain.pem;\n"
            b"    ssl_certificate_key /fixture-tls/control-key.pem;\n",
        ),
    }
)
CHAIN_HOSTS = MappingProxyType(
    {
        "target": "target.opsark.invalid",
        "control": "control.opsark.invalid",
        "default": "unknown.opsark.invalid",
    }
)
_IDENTITY_FIELDS = ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid")
_LAYOUT = {
    ".": {"nginx.conf", "includes", "sites"},
    "includes": {"sites.conf"},
    "sites": {"default.conf", "control.conf"},
}
_SEAL_DIRECTORY = "runtime-context"
_MANIFEST = "manifest.json"
_TLS_DIRECTORY = "tls"
_TLS_GID = 65534
_MAX_TLS_FILE_BYTES = 16_384


@dataclass(frozen=True)
class TLSMaterial:
    cert_sha256: str
    certificate: dict[str, int]
    key: dict[str, int]
    directory: dict[str, int]

    def _manifest(self) -> dict:
        return {
            "cert_sha256": self.cert_sha256,
            "certificate": self.certificate,
            "key": self.key,
            "directory": self.directory,
        }


@dataclass(frozen=True)
class TLSChainMaterial:
    directory: dict[str, int]
    files: dict[str, dict[str, int]]
    leaf_sha256: dict[str, str]
    intermediate_sha256: dict[str, str]
    chain_sha256: dict[str, str]
    root_sha256: str
    root_pem_sha256: str

    def _manifest(self) -> dict:
        # Compact the private seal to retain the existing manifest byte budget.
        # Consumers of the verified context still receive named identity fields.
        return {
            "directory": [self.directory[key] for key in _IDENTITY_FIELDS],
            "files": {
                name: [identity[key] for key in _IDENTITY_FIELDS]
                for name, identity in self.files.items()
            },
            "leaf_sha256": self.leaf_sha256,
            "intermediate_sha256": self.intermediate_sha256,
            "chain_sha256": self.chain_sha256,
            "root_sha256": self.root_sha256,
            "root_pem_sha256": self.root_pem_sha256,
        }


@dataclass(frozen=True)
class RuntimeContext:
    fingerprint: str
    files: dict[str, dict[str, str | int]]
    directories: dict[str, dict[str, int]]
    _machine_sha256: str = field(repr=False)
    tls: TLSMaterial | None = None
    tls_chain: TLSChainMaterial | None = None

    def _payload(self) -> dict:
        payload = {
            "schema_version": 1,
            "machine_sha256": self._machine_sha256,
            "files": self.files,
            "directories": self.directories,
        }
        if self.tls is not None:
            payload["tls"] = self.tls._manifest()
        if self.tls_chain is not None:
            payload["tls_chain"] = self.tls_chain._manifest()
        return payload

    def _manifest(self) -> dict:
        return {**self._payload(), "manifest_sha256": self.fingerprint}


def _require_fixture_policy(policy: config_snapshot.SnapshotPolicy) -> None:
    config_snapshot._check_runtime(config_snapshot.DEFAULT_POLICY)
    if (
        policy.anchor == Path("/")
        or policy.owner_uid != 0
        or policy.config_directory != policy.anchor / "etc/nginx/conf.d"
        or policy.machine_id != policy.anchor / "etc/machine-id"
    ):
        raise config_snapshot.SnapshotError("A private fixture context is required")
    with config_snapshot._directory(policy.anchor, config_snapshot.DEFAULT_POLICY, private=True):
        pass


def _require_absent_tls(workspace: int) -> None:
    try:
        os.stat(_TLS_DIRECTORY, dir_fd=workspace, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise config_snapshot.SnapshotError("TLS dependencies require the sealed TLS fixture")


def _tls_identity(info: os.stat_result, *, directory: bool = False) -> dict[str, int]:
    if (
        info.st_uid != 0
        or info.st_gid != _TLS_GID
        or stat.S_IMODE(info.st_mode) != (0o750 if directory else 0o640)
        or (
            not stat.S_ISDIR(info.st_mode)
            if directory
            else (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not 0 < info.st_size <= _MAX_TLS_FILE_BYTES
            )
        )
    ):
        raise config_snapshot.SnapshotError("TLS fixture ownership or permissions are invalid")
    return config_snapshot._signature(info)


def _reject_tls_acl(fd: int, *, directory: bool = False) -> None:
    names = (
        ("system.posix_acl_access", "system.posix_acl_default")
        if directory
        else ("system.posix_acl_access",)
    )
    for name in names:
        try:
            # Follow only the kernel's held descriptor; fgetxattr rejects an O_PATH fd.
            os.getxattr(f"/proc/self/fd/{fd}", name)
        except OSError as error:
            if error.errno in {errno.ENODATA, errno.EOPNOTSUPP}:
                continue
            raise
        raise config_snapshot.SnapshotError("TLS fixture must not grant extended access")


def _cert_sha256(pem: bytes) -> str:
    lines = pem.splitlines()
    if (
        len(lines) < 3
        or lines[0] != b"-----BEGIN CERTIFICATE-----"
        or lines[-1] != b"-----END CERTIFICATE-----"
    ):
        raise config_snapshot.SnapshotError("TLS fixture requires one public PEM certificate")
    try:
        der = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except binascii.Error:
        raise config_snapshot.SnapshotError("TLS fixture public certificate is invalid") from None
    if not der:
        raise config_snapshot.SnapshotError("TLS fixture public certificate is empty")
    return config_snapshot._sha(der)


def _tls_files(
    policy: config_snapshot.SnapshotPolicy,
    *,
    public_names: set[str],
    key_names: set[str],
) -> tuple[dict[str, int], dict[str, dict[str, int]], dict[str, bytes]]:
    with config_snapshot._directory(policy.anchor / _TLS_DIRECTORY, policy) as directory:
        directory_identity = _tls_identity(os.fstat(directory), directory=True)
        _reject_tls_acl(directory, directory=True)
        expected_names = public_names | key_names
        config_snapshot._members(directory, expected_names)
        identities: dict[str, dict[str, int]] = {}
        contents: dict[str, bytes] = {}
        for name in sorted(public_names):
            expected = _tls_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
            pem, identity = config_snapshot._read(directory, name, _MAX_TLS_FILE_BYTES, policy)
            if identity != expected:
                raise config_snapshot.SnapshotError("TLS fixture public certificate changed")
            identities[name] = identity
            contents[name] = pem
        for name in sorted(key_names):
            # O_PATH yields an identity-only descriptor. It cannot be read or copied.
            fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                key = _tls_identity(os.fstat(fd))
                _reject_tls_acl(fd)
                if key != _tls_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
                    raise config_snapshot.SnapshotError("TLS fixture key identity changed")
                identities[name] = key
            finally:
                os.close(fd)
        config_snapshot._members(directory, expected_names)
        for name, expected in identities.items():
            if _tls_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != expected:
                raise config_snapshot.SnapshotError("TLS fixture dependency changed")
        if _tls_identity(os.fstat(directory), directory=True) != directory_identity:
            raise config_snapshot.SnapshotError("TLS fixture directory changed")
        with config_snapshot._directory(policy.anchor / _TLS_DIRECTORY, policy) as latest:
            if _tls_identity(os.fstat(latest), directory=True) != directory_identity:
                raise config_snapshot.SnapshotError("TLS fixture directory was replaced")
        return directory_identity, identities, contents


def _certificate_blocks(pem: bytes) -> tuple[bytes, bytes]:
    lines = pem.splitlines()
    try:
        end = lines.index(b"-----END CERTIFICATE-----") + 1
    except ValueError:
        raise config_snapshot.SnapshotError(
            "TLS fixture requires a leaf and intermediate"
        ) from None
    return b"\n".join(lines[:end]) + b"\n", b"\n".join(lines[end:]) + b"\n"


def _certificate_pair(pem: bytes) -> tuple[str, str]:
    # Each side accepts exactly one public certificate. A third PEM block,
    # private material, or a missing member cannot be included in the chain.
    leaf, intermediate = _certificate_blocks(pem)
    return _cert_sha256(leaf), _cert_sha256(intermediate)


def _tls_material(
    policy: config_snapshot.SnapshotPolicy, *, tls: bool, tls_chain: bool
) -> tuple[TLSMaterial | None, TLSChainMaterial | None]:
    if tls and tls_chain:
        raise config_snapshot.SnapshotError("Choose exactly one TLS fixture profile")
    if tls:
        directory, files, public = _tls_files(
            policy, public_names={"cert.pem"}, key_names={"key.pem"}
        )
        return TLSMaterial(
            _cert_sha256(public["cert.pem"]), files["cert.pem"], files["key.pem"], directory
        ), None
    if tls_chain:
        directory, files, public = _tls_files(
            policy,
            public_names={"root.pem", *(f"{site}-chain.pem" for site in CHAIN_HOSTS)},
            key_names={f"{site}-key.pem" for site in CHAIN_HOSTS},
        )
        root = _cert_sha256(public["root.pem"])
        leaves: dict[str, str] = {}
        intermediates: dict[str, str] = {}
        chains: dict[str, str] = {}
        for site, host in CHAIN_HOSTS.items():
            pem = public[f"{site}-chain.pem"]
            leaves[host], intermediates[host] = _certificate_pair(pem)
            chains[host] = config_snapshot._sha(pem)
        leaf_set = set(leaves.values())
        intermediate_set = set(intermediates.values())
        if (
            len(leaf_set) != len(CHAIN_HOSTS)
            or leaf_set & intermediate_set
            or root in leaf_set | intermediate_set
        ):
            raise config_snapshot.SnapshotError("TLS fixture needs distinct leaves and CA material")
        return None, TLSChainMaterial(
            directory,
            files,
            leaves,
            intermediates,
            chains,
            root,
            config_snapshot._sha(public["root.pem"]),
        )
    with config_snapshot._directory(policy.anchor, policy, private=True) as workspace:
        _require_absent_tls(workspace)
    return None, None


def _scan(
    policy: config_snapshot.SnapshotPolicy, *, tls: bool = False, tls_chain: bool = False
) -> RuntimeContext:
    runtime = policy.anchor / "runtime"
    machine_sha256 = config_snapshot._machine(policy)
    tls_material, chain_material = _tls_material(policy, tls=tls, tls_chain=tls_chain)
    expected_files = (
        CHAIN_FIXTURE_FILES if tls_chain else TLS_FIXTURE_FILES if tls else FIXTURE_FILES
    )
    with ExitStack() as stack:
        root = stack.enter_context(config_snapshot._directory(runtime, policy))
        opened = {".": root}
        for name in ("includes", "sites"):
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root,
            )
            stack.callback(os.close, fd)
            config_snapshot._check_dir(fd, policy)
            opened[name] = fd
        directories = {
            name: config_snapshot._signature(os.fstat(fd)) for name, fd in opened.items()
        }
        files: dict[str, dict[str, str | int]] = {}
        for name, members in _LAYOUT.items():
            config_snapshot._members(opened[name], members)
        for name, expected in expected_files.items():
            path = PurePosixPath(name)
            fd = opened[str(path.parent)]
            data, signature = config_snapshot._read(fd, path.name, len(expected), policy)
            if data != expected:
                raise config_snapshot.SnapshotError(
                    "Fixture dependency differs from supported bytes"
                )
            files[name] = {**signature, "sha256": config_snapshot._sha(data)}
        for name, signature in files.items():
            path = PurePosixPath(name)
            info = os.stat(path.name, dir_fd=opened[str(path.parent)], follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or any(signature[k] != v for k, v in config_snapshot._signature(info).items())
            ):
                raise config_snapshot.SnapshotError("Fixture dependency changed while reading")
        for name, members in _LAYOUT.items():
            config_snapshot._members(opened[name], members)
            info = os.stat(name, dir_fd=root, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or config_snapshot._signature(info) != directories[name]
            ):
                raise config_snapshot.SnapshotError("Fixture dependency directory changed")
        with config_snapshot._directory(runtime, policy) as latest:
            if config_snapshot._signature(os.fstat(latest)) != directories["."]:
                raise config_snapshot.SnapshotError("Fixture runtime directory was replaced")
        if config_snapshot._machine(policy) != machine_sha256:
            raise config_snapshot.SnapshotError("Fixture machine identity changed")
    if _tls_material(policy, tls=tls, tls_chain=tls_chain) != (tls_material, chain_material):
        raise config_snapshot.SnapshotError("TLS fixture dependencies changed while reading")
    context = RuntimeContext("", files, directories, machine_sha256, tls_material, chain_material)
    return RuntimeContext(
        config_snapshot._sha(config_snapshot._json(context._payload())),
        files,
        directories,
        machine_sha256,
        tls_material,
        chain_material,
    )


def has_context(policy: config_snapshot.SnapshotPolicy) -> bool:
    """Return false only for genuine absence of the richer fixture's context."""
    try:
        _require_fixture_policy(policy)
        with config_snapshot._directory(policy.anchor, policy, private=True) as workspace:
            try:
                os.stat(_SEAL_DIRECTORY, dir_fd=workspace, follow_symlinks=False)
            except FileNotFoundError:
                _require_absent_tls(workspace)
                runtime = policy.anchor / "runtime"
                if not os.path.lexists(runtime):
                    return False
                with config_snapshot._directory(runtime, policy) as directory:
                    config_snapshot._members(directory, {"nginx.conf"})
                return False
        with config_snapshot._directory(
            policy.anchor / _SEAL_DIRECTORY, policy, private=True
        ) as seal:
            config_snapshot._members(seal, {_MANIFEST})
    except OSError:
        raise config_snapshot.SnapshotError("Fixture context is unavailable") from None
    return True


def seal_context(
    policy: config_snapshot.SnapshotPolicy, *, tls: bool = False, tls_chain: bool = False
) -> RuntimeContext:
    """Publish a private context seal once, after rechecking all dependency identities."""
    try:
        _require_fixture_policy(policy)
        context = _scan(policy, tls=tls, tls_chain=tls_chain)

        def recheck() -> None:
            if _scan(policy, tls=tls, tls_chain=tls_chain) != context:
                raise config_snapshot.SnapshotError("Fixture context changed before sealing")

        config_snapshot._publish(
            policy.anchor / _SEAL_DIRECTORY, None, None, context._manifest(), recheck, policy
        )
    except OSError:
        raise config_snapshot.SnapshotError("Fixture context could not be sealed") from None
    return context


def verify_context(policy: config_snapshot.SnapshotPolicy) -> RuntimeContext:
    """Return the live context only when it exactly reproduces its private seal."""
    try:
        _require_fixture_policy(policy)
        with config_snapshot._directory(
            policy.anchor / _SEAL_DIRECTORY, policy, private=True
        ) as seal:
            config_snapshot._members(seal, {_MANIFEST})
            sealed = config_snapshot._read(
                seal, _MANIFEST, config_snapshot.MAX_MANIFEST_BYTES, policy, private=True
            )
            try:
                payload = json.loads(sealed[0], object_pairs_hook=config_snapshot._unique)
            except (ValueError, RecursionError):
                raise config_snapshot.SnapshotError("Fixture context seal is invalid") from None
            if not isinstance(payload, dict):
                raise config_snapshot.SnapshotError("Fixture context seal is invalid")
            context = _scan(policy, tls="tls" in payload, tls_chain="tls_chain" in payload)
            if sealed[0] != config_snapshot._json(context._manifest()) + b"\n" or (
                config_snapshot._read(
                    seal, _MANIFEST, config_snapshot.MAX_MANIFEST_BYTES, policy, private=True
                )
                != sealed
            ):
                raise config_snapshot.SnapshotError("Fixture dependencies do not match their seal")
            config_snapshot._members(seal, {_MANIFEST})
    except OSError:
        raise config_snapshot.SnapshotError("Fixture context could not be verified") from None
    return context
