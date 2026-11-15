"""Checks for an isolated runtime context seal against real Linux file identities."""

import base64
import hashlib
import importlib
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

with pytest.MonkeyPatch.context() as imports:
    imports.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    config_snapshot = importlib.import_module("deploy.nginx.config_snapshot")
    fixture_context = importlib.import_module("deploy.nginx.fixture_context")

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="requires Linux root for real dirfd and owner checks",
)


@pytest.fixture
def policy():
    with TemporaryDirectory(prefix="opsark-context-", dir="/root") as temp:
        anchor = Path(temp)
        configs = anchor / "etc/nginx/conf.d"
        configs.mkdir(parents=True)
        machine = anchor / "etc/machine-id"
        machine.write_text("1" * 32 + "\n", encoding="ascii")
        for name, data in fixture_context.FIXTURE_FILES.items():
            path = anchor / "runtime" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        yield config_snapshot.SnapshotPolicy(anchor, configs, machine, 0)


def test_seal_exact_private_dependency_graph(policy):
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.has_context(policy)
    sealed = fixture_context.seal_context(policy)
    assert fixture_context.has_context(policy)
    assert fixture_context.verify_context(policy) == sealed
    assert set(sealed.files) == set(fixture_context.FIXTURE_FILES)
    assert set(sealed.directories) == {".", "includes", "sites"}
    manifest = policy.anchor / "runtime-context/manifest.json"
    assert manifest.stat().st_mode & 0o777 == 0o600
    assert b"opsark-control" not in manifest.read_bytes()
    assert str(policy.anchor).encode() not in manifest.read_bytes()
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.seal_context(policy)
    assert fixture_context.verify_context(policy) == sealed


def test_identical_bytes_with_new_inode_are_rejected(policy):
    fixture_context.seal_context(policy)
    path = policy.anchor / "runtime/sites/control.conf"
    before = path.stat()
    replacement = path.with_name("replacement.conf")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(before.st_mode & 0o777)
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement.replace(path)
    assert path.stat().st_ino != before.st_ino
    assert path.read_bytes() == fixture_context.FIXTURE_FILES["sites/control.conf"]
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(policy)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("includes/extra.conf", b"include /etc/nginx/nginx.conf;\n"),
        ("includes/sites.conf", b"include /fixture-runtime/sites/*.conf;\n"),
        ("sites/control.conf", b"server { return 200 'alternate'; }\n"),
        ("sites/default.conf", None),
    ],
)
def test_unexpected_dependency_changes_fail_closed(policy, name, replacement):
    fixture_context.seal_context(policy)
    path = policy.anchor / "runtime" / name
    if replacement is None:
        path.unlink()
    else:
        path.write_bytes(replacement)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(policy)


def test_fixture_machine_id_change_is_rejected(policy):
    fixture_context.seal_context(policy)
    policy.machine_id.write_text("2" * 32 + "\n", encoding="ascii")
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(policy)


def test_context_discovery_rejects_symlink_instead_of_falling_back(policy):
    path = policy.anchor / "runtime-context"
    path.symlink_to(policy.anchor / "missing", target_is_directory=True)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.has_context(policy)


def test_legacy_context_absent_without_dependency_tree(policy):
    for name in ("includes/sites.conf", "sites/default.conf", "sites/control.conf"):
        (policy.anchor / "runtime" / name).unlink()
    (policy.anchor / "runtime/includes").rmdir()
    (policy.anchor / "runtime/sites").rmdir()
    assert fixture_context.has_context(policy) is False


_DER = b"fixture-public-der"
_PEM = b"-----BEGIN CERTIFICATE-----\nZml4dHVyZS1wdWJsaWMtZGVy\n-----END CERTIFICATE-----\n"
_OPAQUE_KEY = b"fixture-key-content-never-read"


@pytest.fixture
def tls_policy(policy):
    for name, data in fixture_context.TLS_FIXTURE_FILES.items():
        (policy.anchor / "runtime" / name).write_bytes(data)
    directory = policy.anchor / "tls"
    directory.mkdir()
    os.chown(directory, 0, 65534)
    directory.chmod(0o750)
    for name, data in (("cert.pem", _PEM), ("key.pem", _OPAQUE_KEY)):
        path = directory / name
        path.write_bytes(data)
        os.chown(path, 0, 65534)
        path.chmod(0o640)
    return policy


def test_tls_seal_contains_public_leaf_digest_and_key_identity_only(tls_policy, monkeypatch):
    real_open = os.open
    key_opens = []

    def checked_open(path, flags, *args, **kwargs):
        if path == "key.pem":
            assert flags & os.O_PATH and flags & os.O_NOFOLLOW
            key_opens.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked_open)
    sealed = fixture_context.seal_context(tls_policy, tls=True)
    assert fixture_context.verify_context(tls_policy) == sealed
    assert key_opens and sealed.tls is not None
    assert sealed.tls.cert_sha256 == hashlib.sha256(_DER).hexdigest()
    assert sealed.tls.key["mode"] == 0o640 and sealed.tls.key["gid"] == 65534
    manifest = (tls_policy.anchor / "runtime-context/manifest.json").read_bytes()
    assert _OPAQUE_KEY not in manifest and _PEM not in manifest
    assert hashlib.sha256(_OPAQUE_KEY).hexdigest().encode() not in manifest


def test_unsealed_tls_fixture_never_falls_back_to_http(tls_policy):
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.has_context(tls_policy)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.seal_context(tls_policy)


@pytest.mark.parametrize("name", ["tls", "tls/cert.pem", "tls/key.pem"])
def test_tls_ownership_or_permission_drift_is_rejected(tls_policy, name):
    fixture_context.seal_context(tls_policy, tls=True)
    (tls_policy.anchor / name).chmod(0o755 if name == "tls" else 0o644)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(tls_policy)


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_tls_key_links_are_rejected(tls_policy, link):
    key = tls_policy.anchor / "tls/key.pem"
    outside = tls_policy.anchor / "fixture-key"
    key.rename(outside)
    if link == "symlink":
        key.symlink_to(outside)
    else:
        key.hardlink_to(outside)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.seal_context(tls_policy, tls=True)


def test_same_size_key_write_revokes_tls_seal_even_with_restored_mtime(tls_policy):
    fixture_context.seal_context(tls_policy, tls=True)
    key = tls_policy.anchor / "tls/key.pem"
    before = key.stat()
    key.write_bytes(b"?" * before.st_size)
    os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(tls_policy)


def test_public_pem_must_not_include_an_extra_block(tls_policy):
    cert = tls_policy.anchor / "tls/cert.pem"
    cert.write_bytes(_PEM + _PEM)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.seal_context(tls_policy, tls=True)


@pytest.mark.parametrize("name", ["tls", "tls/key.pem"])
def test_tls_extended_acl_is_rejected(tls_policy, monkeypatch, name):
    path = str(tls_policy.anchor / name)
    original = os.getxattr

    def with_acl(fd_path, attribute):
        if os.readlink(fd_path) == path:
            return b"unexpected extended ACL"
        return original(fd_path, attribute)

    monkeypatch.setattr(os, "getxattr", with_acl)
    with pytest.raises(config_snapshot.SnapshotError, match="extended access"):
        fixture_context.seal_context(tls_policy, tls=True)


def pem(content):
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(content)
        + (b"\n-----END CERTIFICATE-----\n")
    )


@pytest.fixture
def chain_policy(policy):
    for name, data in fixture_context.CHAIN_FIXTURE_FILES.items():
        (policy.anchor / "runtime" / name).write_bytes(data)
    directory = policy.anchor / "tls"
    directory.mkdir()
    os.chown(directory, 0, 65534)
    directory.chmod(0o750)
    materials = {"root.pem": pem(b"fixture-root")}
    for role in fixture_context.CHAIN_HOSTS:
        materials[f"{role}-chain.pem"] = pem(f"fixture-leaf-{role}".encode()) + pem(
            b"fixture-intermediate"
        )
        materials[f"{role}-key.pem"] = _OPAQUE_KEY
    for name, data in materials.items():
        path = directory / name
        path.write_bytes(data)
        os.chown(path, 0, 65534)
        path.chmod(0o640)
    return policy


def test_chain_seal_binds_per_host_leaf_and_ordered_public_file(chain_policy, monkeypatch):
    real_open = os.open
    key_opens = set()

    def checked_open(path, flags, *args, **kwargs):
        if isinstance(path, str) and path.endswith("-key.pem"):
            assert flags & os.O_PATH and flags & os.O_NOFOLLOW
            key_opens.add(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked_open)
    sealed = fixture_context.seal_context(chain_policy, tls_chain=True)
    assert fixture_context.verify_context(chain_policy) == sealed
    assert fixture_context.has_context(chain_policy)
    assert sealed.tls is None and sealed.tls_chain is not None
    assert key_opens == {f"{role}-key.pem" for role in fixture_context.CHAIN_HOSTS}
    chain = sealed.tls_chain
    assert chain.root_sha256 == hashlib.sha256(b"fixture-root").hexdigest()
    assert chain.root_pem_sha256 == hashlib.sha256(pem(b"fixture-root")).hexdigest()
    for role, host in fixture_context.CHAIN_HOSTS.items():
        leaf = f"fixture-leaf-{role}".encode()
        intermediate = b"fixture-intermediate"
        assert chain.leaf_sha256[host] == hashlib.sha256(leaf).hexdigest()
        assert chain.intermediate_sha256[host] == hashlib.sha256(intermediate).hexdigest()
        assert chain.chain_sha256[host] == hashlib.sha256(pem(leaf) + pem(intermediate)).hexdigest()
        assert chain.files[f"{role}-key.pem"]["mode"] == 0o640
    manifest = (chain_policy.anchor / "runtime-context/manifest.json").read_bytes()
    assert len(manifest) <= config_snapshot.MAX_MANIFEST_BYTES
    assert _OPAQUE_KEY not in manifest and b"BEGIN CERTIFICATE" not in manifest


@pytest.mark.parametrize(
    "replacement",
    [
        pem(b"fixture-leaf-target"),
        pem(b"fixture-leaf-control") + pem(b"fixture-intermediate"),
        pem(b"fixture-leaf-target") + pem(b"fixture-root"),
        pem(b"fixture-leaf-target") + pem(b"fixture-intermediate") + pem(b"extra"),
    ],
)
def test_invalid_public_chain_is_refused(chain_policy, replacement):
    (chain_policy.anchor / "tls/target-chain.pem").write_bytes(replacement)
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.seal_context(chain_policy, tls_chain=True)


def test_chain_rotation_revokes_original_seal(chain_policy):
    sealed = fixture_context.seal_context(chain_policy, tls_chain=True)
    target = chain_policy.anchor / "tls/target-chain.pem"
    target.write_bytes(pem(b"new-leaf-target") + pem(b"fixture-intermediate"))
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.verify_context(chain_policy)
    seal = chain_policy.anchor / "runtime-context"
    (seal / "manifest.json").unlink()
    seal.rmdir()
    replacement = fixture_context.seal_context(chain_policy, tls_chain=True)
    assert replacement.fingerprint != sealed.fingerprint
    assert fixture_context.verify_context(chain_policy) == replacement


def test_chain_never_falls_back_to_shared_or_unsealed_tls(chain_policy):
    with pytest.raises(config_snapshot.SnapshotError):
        fixture_context.has_context(chain_policy)
    for options in ({}, {"tls": True}, {"tls": True, "tls_chain": True}):
        with pytest.raises(config_snapshot.SnapshotError):
            fixture_context.seal_context(chain_policy, **options)
