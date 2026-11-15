"""Root-helper trust boundaries with temporary files and explicit native checks."""

import copy
import errno
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "deploy/vulnerability/core.py"
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
DEB822 = (
    "# Ubuntu sources generated for this test\n"
    "# Signed-By: /untrusted/comment-is-not-an-option.gpg\n"
    "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\n"
    "Suites: noble noble-updates noble-security\nComponents: main universe\n"
    "Signed-By: " + KEYRING + "\n"
)


@pytest.fixture
def core(monkeypatch):
    spec = importlib.util.spec_from_file_location("opsark_patch_core_contract", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


class NativeSectionContract:
    """Only the keys() contract is supported, as with distro apt_pkg.TagSection."""

    def __init__(self, text):
        assert text.endswith("\n\n"), "Native control records require explicit EOF framing"
        assert not any(line.lstrip().startswith("#") for line in text.splitlines())
        self.fields = {}
        current = None
        for line in text.splitlines():
            if not line:
                continue
            if line[0].isspace():
                if current is None:
                    raise ValueError("Continuation without a field")
                self.fields[current] += "\n" + line
            else:
                current, value = line.split(":", 1)
                self.fields[current] = value.strip()

    def keys(self):
        return self.fields.keys()

    def __getitem__(self, key):
        return self.fields[key]


@pytest.fixture
def apt_sources(core, tmp_path, monkeypatch):
    directory = tmp_path / "etc/apt/sources.list.d"
    directory.mkdir(parents=True)
    calls = []

    def section(text):
        calls.append(text)
        return NativeSectionContract(text)

    config = {"valid_until": True}
    native = SimpleNamespace(
        TagSection=section,
        config=SimpleNamespace(find_b=lambda _key, _default: config["valid_until"]),
    )
    monkeypatch.setattr(core, "importlib", SimpleNamespace(import_module=lambda _name: native))
    monkeypatch.setattr(core, "Path", lambda path: tmp_path / str(path).lstrip("/"))
    monkeypatch.setattr(core, "read_bytes", lambda path, *_args, **_kwargs: path.read_bytes())
    return SimpleNamespace(
        core=core, root=tmp_path, directory=directory, calls=calls, config=config
    )


def test_deb822_comments_are_removed_but_native_record_framing_is_supplied(apt_sources):
    (apt_sources.directory / "ubuntu.sources").write_text(DEB822)
    apt_sources.core.verify_sources()
    assert len(apt_sources.calls) == 1
    normalized = apt_sources.calls[0]
    assert normalized.endswith("\n\n")
    assert "#" not in normalized
    assert "URIs: http://archive.ubuntu.com/ubuntu" in normalized
    assert "Signed-By: " + KEYRING in normalized


@pytest.mark.parametrize(
    "replacement",
    [
        "Signed-By: " + KEYRING + "\n /untrusted/additional-key.gpg\n",
        "Signed-By: " + KEYRING + "\nSigned-By: " + KEYRING + "\n",
        "Signed-By: /untrusted/replacement.gpg\n",
        "",
    ],
)
def test_deb822_signed_by_must_be_one_exact_key_not_a_continuation_or_duplicate(
    apt_sources, replacement
):
    text = DEB822.replace("Signed-By: " + KEYRING + "\n", replacement)
    (apt_sources.directory / "ubuntu.sources").write_text(text)
    with pytest.raises(apt_sources.core.Rejected, match="pinned"):
        apt_sources.core.verify_sources()
    if " /untrusted/additional-key.gpg" in replacement:
        assert "\n /untrusted/additional-key.gpg" in apt_sources.calls[0]


def test_disabled_deb822_source_does_not_supply_trust(apt_sources):
    (apt_sources.directory / "ubuntu.sources").write_text("Enabled: no\n" + DEB822)
    with pytest.raises(apt_sources.core.Rejected, match="could not be established"):
        apt_sources.core.verify_sources()


@pytest.mark.parametrize(
    "line",
    [
        "deb http://archive.ubuntu.com/ubuntu noble main # signed-by=" + KEYRING,
        "deb [not-signed-by=" + KEYRING + "] http://archive.ubuntu.com/ubuntu noble main",
        "deb [signed-by="
        + KEYRING
        + " signed-by=/untrusted/extra.gpg] http://archive.ubuntu.com/ubuntu noble main",
    ],
)
def test_legacy_comment_or_option_substring_cannot_fake_the_archive_key(apt_sources, line):
    (apt_sources.root / "etc/apt/sources.list").write_text(line + "\n")
    with pytest.raises(apt_sources.core.Rejected, match="keyring"):
        apt_sources.core.verify_sources()


def test_explicit_legacy_key_is_allowed_and_expired_index_policy_is_not(apt_sources):
    (apt_sources.root / "etc/apt/sources.list").write_text(
        "deb [signed-by=" + KEYRING + "] http://security.ubuntu.com/ubuntu noble-security main\n"
    )
    apt_sources.core.verify_sources()
    assert apt_sources.calls == []
    apt_sources.config["valid_until"] = False
    with pytest.raises(apt_sources.core.Rejected, match="could not be established"):
        apt_sources.core.verify_sources()


def test_similar_third_party_hostname_is_not_an_approved_ubuntu_source(apt_sources):
    (apt_sources.directory / "ubuntu.sources").write_text(
        DEB822.replace("archive.ubuntu.com/", "archive.ubuntu.com.evil.invalid/")
    )
    with pytest.raises(apt_sources.core.Rejected, match="could not be established"):
        apt_sources.core.verify_sources()


@pytest.mark.parametrize(
    "filename",
    [
        "activation.py",
        "automatic_policy.py",
        "recovery.py",
        "core.py",
        "scan.py",
        "agent.py",
        "ssh_entry.py",
        "worker.py",
        "pre_install.py",
        "transaction_hook.py",
    ],
)
def test_reviewed_source_digest_binds_every_runtime_helper(core, tmp_path, monkeypatch, filename):
    monkeypatch.setattr(core, "LIB", tmp_path)
    monkeypatch.setattr(core, "read_bytes", lambda path, **_kwargs: path.read_bytes())
    for name in core.SOURCE_FILES:
        (tmp_path / name).write_bytes(b"# reviewed fixture\n")
    expected = hashlib.sha256(
        json.dumps(
            {
                name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
                for name in core.SOURCE_FILES
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert core.source_digest() == expected
    (tmp_path / filename).write_bytes(b"# modified after capability review\n")
    assert core.source_digest() != expected


@pytest.fixture
def policy_fixture(core, tmp_path, monkeypatch):
    machine, key = b"test-only-machine-id\n", b"test-only-archive-public-key"
    (tmp_path / "machine-id").write_bytes(machine)
    (tmp_path / "keyring.gpg").write_bytes(key)
    policy = {
        "schema_version": 1,
        "driver": core.DRIVER,
        "driver_source_digest": "a" * 64,
        "host_id": "test-host",
        "machine_id_digest": hashlib.sha256(machine).hexdigest(),
        "enabled": True,
        "allowed_packages": ["libbrotli1"],
        "max_packages": 1,
        "allow_service_restart": True,
        "allow_reboot": False,
        "ubuntu_keyring_sha256": hashlib.sha256(key).hexdigest(),
        "advisory_ids": ["USN-8956-1"],
        "services": ["ssh.service"],
        "health_checks": [{"id": "fixture-health"}],
    }

    def path(value):
        return tmp_path / ("machine-id" if str(value) == "/etc/machine-id" else "keyring.gpg")

    monkeypatch.setattr(core, "Path", path)
    monkeypatch.setattr(core, "directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(core, "read_json", lambda *_args: copy.deepcopy(policy))
    monkeypatch.setattr(core, "source_digest", lambda: "a" * 64)
    monkeypatch.setattr(core, "read_bytes", lambda value, **_kwargs: value.read_bytes())
    return SimpleNamespace(core=core, policy=policy, root=tmp_path)


def test_policy_binds_source_code_machine_and_archive_key(policy_fixture):
    fixture = policy_fixture
    assert fixture.core.load_policy() == fixture.policy
    fixture.policy["driver_source_digest"] = "b" * 64
    with pytest.raises(fixture.core.Rejected, match="code changed"):
        fixture.core.load_policy()
    fixture.policy["driver_source_digest"] = "a" * 64
    (fixture.root / "machine-id").write_bytes(b"replacement machine")
    with pytest.raises(fixture.core.Rejected, match="identity changed"):
        fixture.core.load_policy()


def test_policy_rejects_an_archive_key_change(policy_fixture):
    (policy_fixture.root / "keyring.gpg").write_bytes(b"replacement key")
    with pytest.raises(policy_fixture.core.Rejected, match="keyring changed"):
        policy_fixture.core.load_policy()


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"max_packages": True},
        {"enabled": "true"},
        {"asset_kind": "unreviewed"},
    ],
)
def test_policy_schema_does_not_coerce_privilege_or_scope_fields(policy_fixture, change):
    policy_fixture.policy.update(change)
    with pytest.raises(policy_fixture.core.Rejected):
        policy_fixture.core.load_policy()


@pytest.mark.parametrize(
    "mode,uid,private,accepted",
    [
        (stat.S_IFDIR | 0o700, 0, True, True),
        (stat.S_IFDIR | 0o755, 0, False, True),
        (stat.S_IFDIR | 0o755, 0, True, False),
        (stat.S_IFDIR | 0o775, 0, False, False),
        (stat.S_IFDIR | 0o700, 1000, True, False),
        (stat.S_IFLNK | 0o700, 0, True, False),
    ],
)
def test_root_directory_type_owner_and_permission_contract(core, mode, uid, private, accepted):
    target = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=uid))
    if accepted:
        core.directory(target, private=private)
    else:
        with pytest.raises(core.Rejected):
            core.directory(target, private=private)


@pytest.mark.parametrize(
    "changes,private,limit,accepted",
    [
        ({}, True, 100, True),
        ({"st_mode": stat.S_IFREG | 0o644}, False, 100, True),
        ({"st_mode": stat.S_IFREG | 0o644}, True, 100, False),
        ({"st_mode": stat.S_IFREG | 0o622}, False, 100, False),
        ({"st_uid": 1000}, True, 100, False),
        ({"st_nlink": 2}, True, 100, False),
        ({"st_mode": stat.S_IFIFO | 0o600}, True, 100, False),
        ({}, True, 1, False),
        ({"st_size": 0}, True, 1, False),
    ],
)
def test_file_read_validates_simulated_root_metadata_and_bounded_bytes(
    core, tmp_path, monkeypatch, changes, private, limit, accepted
):
    path = tmp_path / "root-private-record"
    payload = b"private fixture record"
    path.write_bytes(payload)
    descriptor = os.open(path, os.O_RDONLY)
    metadata = {
        "st_mode": stat.S_IFREG | 0o600,
        "st_uid": 0,
        "st_nlink": 1,
        "st_size": len(payload),
        "st_mtime_ns": 1,
    } | changes
    proxy = SimpleNamespace(
        O_RDONLY=os.O_RDONLY,
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
        O_NONBLOCK=getattr(os, "O_NONBLOCK", 0),
        open=lambda *_args: descriptor,
        fstat=lambda _fd: SimpleNamespace(**metadata),
        fdopen=os.fdopen,
        close=os.close,
    )
    monkeypatch.setattr(core, "os", proxy)
    if accepted:
        assert core.read_bytes(path, limit, private=private) == payload
    else:
        with pytest.raises(core.Rejected):
            core.read_bytes(path, limit, private=private)
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX O_NOFOLLOW symlink rejection")
def test_real_symlink_is_rejected_before_opening_its_target(core, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"fixture only")
    link = tmp_path / "linked"
    link.symlink_to(target)
    with pytest.raises(OSError) as error:
        core.read_bytes(link, private=False)
    assert error.value.errno == errno.ELOOP


@pytest.mark.parametrize(
    "started,boot,expected",
    [(99, "boot", False), (100, "boot", False), (101, "boot", True), (101, "other", False)],
)
@pytest.mark.parametrize("executable", ["/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"])
def test_new_ssh_proof_requires_same_boot_and_strictly_later_connection_process(
    core, tmp_path, monkeypatch, started, boot, expected, executable
):
    def path(value):
        if str(value).endswith("boot_id"):
            return SimpleNamespace(read_text=lambda: "boot")
        pid = int(str(value).split("/")[2])
        fields = ["S", "200" if pid == 100 else "1", *(["0"] * 17), str(started)]
        return SimpleNamespace(
            read_text=lambda: f"{pid} (session (with spaces)) " + " ".join(fields)
        )

    monkeypatch.setattr(core, "Path", path)
    monkeypatch.setattr(
        core,
        "os",
        SimpleNamespace(
            getppid=lambda: 100,
            readlink=lambda value: "/usr/bin/sudo" if "/100/" in value else executable,
        ),
    )
    assert core.fresh_ssh_connection(100, boot) is expected


@pytest.mark.parametrize(
    "executable",
    [
        "/tmp/sshd-session",  # noqa: S108 -- untrusted executable rejection fixture.
        "/usr/local/bin/sshd-session",
        "/usr/lib/openssh/sshd-session (deleted)",
        "/usr/lib/openssh/sshd-auth",
        "/usr/bin/sh",
    ],
)
def test_new_ssh_proof_rejects_lookalikes_and_unrecognized_ancestors(core, monkeypatch, executable):
    def path(value):
        if str(value).endswith("boot_id"):
            return SimpleNamespace(read_text=lambda: "boot")
        return SimpleNamespace(read_text=lambda: "2 (session) S 1 " + "0 " * 17 + "101")

    monkeypatch.setattr(core, "Path", path)
    monkeypatch.setattr(
        core, "os", SimpleNamespace(getppid=lambda: 2, readlink=lambda _: executable)
    )
    assert core.fresh_ssh_connection(100, "boot") is False


@pytest.mark.skipif(sys.platform != "linux", reason="Actual distribution python3-apt parser")
def test_distribution_tagsection_parses_normalized_commented_deb822_sources(tmp_path):
    python = Path("/usr/bin/python3")
    if not python.exists():
        pytest.skip("System Python unavailable")
    probe = subprocess.run(  # noqa: S603 - fixed system probe
        [str(python), "-I", "-c", "import apt_pkg"], capture_output=True, check=False
    )
    if probe.returncode:
        pytest.skip("System python3-apt unavailable")
    directory = tmp_path / "etc/apt/sources.list.d"
    directory.mkdir(parents=True)
    (directory / "ubuntu.sources").write_text(DEB822)
    code = (
        "import importlib.util;from pathlib import Path;"
        "spec=importlib.util.spec_from_file_location('core_contract'," + repr(str(SOURCE)) + ");"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
        "root=Path(" + repr(str(tmp_path)) + ");"
        "module.Path=lambda value:root/str(value).lstrip('/');"
        "module.read_bytes=lambda path,*args,**kwargs:path.read_bytes();"
        "module.verify_sources()"
    )
    result = subprocess.run(  # noqa: S603 - fixed asset in an isolated interpreter
        [str(python), "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
