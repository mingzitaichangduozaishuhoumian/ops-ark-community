"""Offline backups use native authenticated age; all credentials and stores are synthetic."""

import copy
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_automatic_ai as automatic_fixtures
import test_vulnerability_ai_service as service_fixtures
from test_storage import make_receipt, make_report
from test_store_transfer import directory_digests, transfer

from opsark.baselines import BaselineStore
from opsark.security_ai_store import SecurityAIStore
from opsark.security_store import SecurityStore
from opsark.storage import ReportStore
from opsark.vulnerability_store import VulnerabilityStore
from opsark.web_security_store import WebSecurityStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import sealed_backup as sealed  # noqa: E402 -- exact test checkout for isolated pytest.

SQL_MARKER = "INSERT INTO fake_customer VALUES ('SYNTHETIC-PRIVATE-DB-ONLY');"
INLINE_KEY = "synthetic-inline-provider-key-never-live"
EXCLUDED_KEY = "synthetic-excluded-deployment-secret-never-live"
HASHES = {
    "nt": {
        "age": "2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0",
        "age-keygen": "1549c7049be32695594bedd09bbd352a94b6013a9d5c43364f3c6cd7a09ab61c",
    },
    "posix": {
        "age": "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c",
        "age-keygen": "0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899",
    },
}


def private_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_file(path, body):
    path.write_bytes(body)
    path.chmod(0o600)
    return path


def restrict_owned_windows_fixture(path):
    """Set a real protected ACL on this test's new empty directory, never a deployment."""
    if os.name != "nt":
        return
    assert path.is_absolute() and path.is_dir() and not any(path.iterdir())
    system = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    result = subprocess.run(  # noqa: S603 -- fixed Windows identity query, no shell.
        [str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        timeout=5,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, "Current fixture owner could not be verified"
    match = re.search(rb"S-1-5-(?:[0-9]+-)*[0-9]+", result.stdout)
    assert match is not None
    sid = match[0].decode("ascii")
    # These are numeric SIDs, avoiding account-name or domain resolution.
    result = subprocess.run(  # noqa: S603 -- fixed ACL operation on an empty owned pytest directory.
        [
            str(system / "icacls.exe"),
            str(path),
            "/inheritance:r",
            "/grant:r",
            "*" + sid + ":(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/Q",
        ],
        capture_output=True,
        timeout=5,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, "Private fixture ACL could not be applied"


def public_result(value, directory):
    assert set(value) <= {
        "schema_version",
        "backup_id",
        "profile",
        "cipher_sha256",
        "cipher_bytes",
        "database_count",
        "file_count",
        "snapshot_verified",
        "configuration_included",
        "image_material_included",
        "credential_files_included",
        "remote_root_state_included",
        "quiescence_operator_confirmed",
        "sealed",
        "plaintext_tar_written",
        "restored",
        "full_authentication_before_extraction",
        "authenticated_plaintext_bytes",
        "configuration_activated",
        "image_loaded",
        "credential_files_restored",
        "leases_cleared",
        "inline_config_secrets_may_be_present",
        "ciphertext_matched",
        "content_authenticated",
    }
    text = json.dumps(value, ensure_ascii=True, allow_nan=False)
    assert all(
        marker not in text
        for marker in (
            SQL_MARKER,
            INLINE_KEY,
            EXCLUDED_KEY,
            "AGE-SECRET-KEY-",
            str(directory),
            "private-host-canary",
        )
    )
    assert str(directory).replace("\\", "\\\\") not in text


@pytest.fixture(scope="session")
def native_tools():
    configured = os.environ.get("OPSARK_TEST_AGE_DIR")
    if not configured:
        pytest.skip("Set OPSARK_TEST_AGE_DIR to independently verified native age v1.3.2 tools")
    root = Path(configured)
    suffix = ".exe" if os.name == "nt" else ""
    tools = {name: root / (name + suffix) for name in ("age", "age-keygen")}
    assert all(path.is_absolute() and path.is_file() for path in tools.values())
    expected = HASHES[os.name]
    assert all(digest(path) == expected[name] for name, path in tools.items())
    return SimpleNamespace(age=tools["age"], keygen=tools["age-keygen"], hashes=expected)


def native(command, *, input_data=None):
    # Only the independently hashed tools above or the current interpreter are used.
    result = subprocess.run(  # noqa: S603 -- fixed native fixture executable, shell-free.
        command,
        input=input_data,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, "Synthetic native fixture command failed"
    assert all(
        marker.encode() not in result.stderr
        for marker in (SQL_MARKER, INLINE_KEY, EXCLUDED_KEY, "AGE-SECRET-KEY-")
    )
    return result.stdout


def new_identity(directory, tools, name):
    identity = directory / name
    native([str(tools.keygen), "-o", str(identity)])
    identity.chmod(0o600)
    public = native([str(tools.keygen), "-y", str(identity)])
    assert public.startswith(b"age1") and public.count(b"\n") == 1
    return identity, public


@pytest.fixture
def backup_case(tmp_path, monkeypatch, native_tools):
    restrict_owned_windows_fixture(tmp_path)
    source = private_directory(tmp_path / "source")
    e = service_fixtures.env.__wrapped__(source, monkeypatch)  # ty: ignore[unresolved-attribute]
    e = automatic_fixtures.gated.__wrapped__(e, source)  # ty: ignore[unresolved-attribute]
    assert automatic_fixtures.require(e) is not None
    assert e.auto.ai_quotas("server-a", e.policy.automatic.grant_id, now=e.now)["total_used"] == 1
    assert e.auto.claim_monitor("e" * 32, now=e.now)
    e.auto.set_host_state("server-a", {"host_id": "server-a", "paused": True, "reason": "fixture"})
    # The fixture's independent stores become the canonical offline deployment files.
    for src, name in ((e.auto.path, "automatic.sqlite3"), (e.modes.path, "automation.sqlite3")):
        shutil.copyfile(src, source / name)
        (source / name).chmod(0o600)
    reports = ReportStore(source / "reports.sqlite3")
    report = make_report()
    report.evidence[0].output = SQL_MARKER
    reports.save(report)
    reports.save_handoff_receipt(make_receipt())
    BaselineStore(source / "baselines.sqlite3")
    security = SecurityStore(source / "security.sqlite3")
    assert security.claim_monitor("f" * 32, e.now)
    web = WebSecurityStore(source / "web-security.sqlite3")
    assert web.claim_monitor("f" * 32, e.now)
    SecurityAIStore(source / "security-ai.sqlite3")
    watch = VulnerabilityStore(source / "vulnerability-watch.sqlite3")
    assert watch.claim_monitor("f" * 32, now=e.now)
    private_file(source / "access-token", EXCLUDED_KEY.encode())
    snapshot = tmp_path / "snapshot"
    manifest = transfer.snapshot(source, snapshot)
    assert set(manifest["databases"]) == set(transfer.DATABASES)
    assert transfer.verify_snapshot(snapshot)["database_count"] == 10
    identity, recipient = new_identity(tmp_path, native_tools, "identity")
    wrong, _ = new_identity(tmp_path, native_tools, "wrong-identity")
    recipient_file = private_file(tmp_path / "recipient", recipient)
    return SimpleNamespace(
        root=tmp_path,
        source=source,
        snapshot=snapshot,
        tools=native_tools,
        identity=identity,
        wrong_identity=wrong,
        recipient_file=recipient_file,
        ciphertext=tmp_path / "sealed.age",
        source_before=directory_digests(source),
        snapshot_before=directory_digests(snapshot),
    )


def seal_case(case, **options):
    return sealed.seal(
        case.snapshot,
        case.recipient_file,
        digest(case.recipient_file),
        case.tools.age,
        case.tools.hashes["age"],
        case.ciphertext,
        confirm_quiescent=True,
        **options,
    )


def restore_case(case, output=None, identity=None, ciphertext=None):
    source = ciphertext or case.ciphertext
    return sealed.restore(
        source,
        digest(source),
        identity or case.identity,
        case.tools.age,
        case.tools.hashes["age"],
        case.tools.keygen,
        case.tools.hashes["age-keygen"],
        output or case.root / "restored",
    )


def rows(path, table):
    assert table in {
        "reports",
        "handoff_receipts",
        "automation_mode",
        "automation_audit",
        "automatic_ai_requests",
        "automatic_host_states",
        "automatic_monitor_lease",
        "monitor_lease",
    }
    with closing(sqlite3.connect(path)) as database:
        return database.execute("SELECT * FROM " + table).fetchall()  # noqa: S608 -- test allowlist


def test_real_native_round_trip_preserves_all_ten_stores_and_safety_history(backup_case, capsys):
    c = backup_case
    result = seal_case(c)
    public_result(result, c.root)
    assert c.ciphertext.read_bytes().startswith(b"age-encryption.org/v1\n")
    check = sealed.check_ciphertext(c.ciphertext, digest(c.ciphertext))
    public_result(check, c.root)
    restored = restore_case(c)
    public_result(restored, c.root)
    output = c.root / "restored"
    assert directory_digests(c.source) == c.source_before
    assert directory_digests(c.snapshot) == c.snapshot_before
    # Profiles have fixed members; find the one exact recovered ten-store directory.
    candidates = [output, *[p for p in output.iterdir() if p.is_dir()]]
    recovered = [p for p in candidates if (p / "reports.sqlite3").is_file()]
    assert len(recovered) == 1
    recovered = recovered[0]
    assert directory_digests(recovered) == c.snapshot_before
    assert transfer.verify_snapshot(recovered)["database_count"] == 10
    for db, table in (
        ("reports.sqlite3", "reports"),
        ("reports.sqlite3", "handoff_receipts"),
        ("automation.sqlite3", "automation_mode"),
        ("automation.sqlite3", "automation_audit"),
        ("automatic.sqlite3", "automatic_ai_requests"),
        ("automatic.sqlite3", "automatic_host_states"),
        ("automatic.sqlite3", "automatic_monitor_lease"),
        ("security.sqlite3", "monitor_lease"),
    ):
        expected = rows(c.snapshot / db, table)
        assert expected and rows(recovered / db, table) == expected
    assert not list(output.rglob("access-token"))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("damage", ["wrong_identity", "last_tag", "truncated"])
def test_authentication_failure_never_calls_extractor_or_publishes(
    backup_case, monkeypatch, damage
):
    c = backup_case
    seal_case(c)
    if damage != "wrong_identity":
        original = c.ciphertext.read_bytes()
        damaged = (
            original[:-1] if damage == "truncated" else original[:-1] + bytes([original[-1] ^ 1])
        )
        private_file(c.ciphertext, damaged)
    calls = []

    def never_extract(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Unauthenticated plaintext reached extraction")

    monkeypatch.setattr(sealed, "_extract_archive", never_extract)
    output = c.root / "unauthenticated-output"
    with pytest.raises(sealed.BackupError):
        restore_case(c, output, c.wrong_identity if damage == "wrong_identity" else c.identity)
    assert not calls and not output.exists()
    assert directory_digests(c.snapshot) == c.snapshot_before


def test_authentication_finishes_before_the_second_pass_can_extract(backup_case, monkeypatch):
    c = backup_case
    seal_case(c)
    executions, extractions = [], []
    popen, extract = subprocess.Popen, sealed._extract_archive

    def native_process(command, *args, **kwargs):
        executions.append(tuple(str(value) for value in command))
        return popen(command, *args, **kwargs)

    def authenticated_extract(*args, **kwargs):
        assert sum("--decrypt" in argv or "-d" in argv for argv in executions) >= 2
        extractions.append(True)
        return extract(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", native_process)
    monkeypatch.setattr(sealed, "_extract_archive", authenticated_extract)
    restore_case(c)
    assert extractions == [True]


def authenticated_archive(case, plaintext):
    public = case.recipient_file.read_bytes().strip().decode("ascii")
    encrypted = native(
        [str(case.tools.age), "--encrypt", "--recipient", public], input_data=plaintext
    )
    return private_file(case.root / "malicious.age", encrypted)


def archive_members(case):
    plaintext = native(
        [str(case.tools.age), "--decrypt", "--identity", str(case.identity), str(case.ciphertext)]
    )
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as archive:
        members = []
        for member in archive:
            assert member.isfile()
            content = archive.extractfile(member)
            assert content is not None
            members.append((copy.copy(member), content.read()))
        return members


def malicious_archive(members, attack, absolute_target):
    output = io.BytesIO()
    if attack == "oversize":
        # A valid USTAR header with a huge declaration, not a huge memory allocation.
        for info, content in members:
            if info.name.endswith(".sqlite3"):
                info = copy.copy(info)
                info.size = 4 * 1024**3 + 1
                output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                break
            output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
            output.write(content + b"\0" * (-len(content) % 512))
        return output.getvalue() + b"\0" * 1024
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for info, content in members:
            archive.addfile(info, io.BytesIO(content))
        info = tarfile.TarInfo("../escape")
        info.mode = 0o600
        content = b"synthetic-untrusted-archive-member"
        if attack == "absolute":
            # Even a regressed implementation could only touch this owned test path.
            info.name = absolute_target.as_posix()
        elif attack == "backslash":
            info.name = "..\\escape"
        elif attack == "duplicate":
            info, content = members[0]
        elif attack in {"symlink", "hardlink"}:
            info.name = "forbidden-link"
            info.type = tarfile.SYMTYPE if attack == "symlink" else tarfile.LNKTYPE
            info.linkname = "../escape"
            content = b""
        elif attack == "pax":
            info.name = "pax-record"
            info.type = tarfile.XHDTYPE
            content = b"18 path=../escape\n"
        elif attack == "trailing_nonzero":
            content = None
        else:
            assert attack == "traversal"
        if content is not None:
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    result = output.getvalue()
    return result + b"X" * 512 if attack == "trailing_nonzero" else result


@pytest.mark.parametrize(
    "attack",
    [
        "traversal",
        "absolute",
        "backslash",
        "symlink",
        "hardlink",
        "pax",
        "duplicate",
        "trailing_nonzero",
        "oversize",
    ],
)
def test_authenticated_malicious_archive_is_never_published(backup_case, attack):
    c = backup_case
    seal_case(c)
    escaped = c.root / "owned-absolute-escape"
    source = authenticated_archive(c, malicious_archive(archive_members(c), attack, escaped))
    output = c.root / "malicious-output"
    with pytest.raises(sealed.BackupError):
        restore_case(c, output, ciphertext=source)
    assert not output.exists() and not (c.root / "escape").exists() and not escaped.exists()
    assert directory_digests(c.snapshot) == c.snapshot_before


def test_trusted_ciphertext_digest_is_required_even_for_otherwise_valid_age(backup_case):
    c = backup_case
    seal_case(c)
    with pytest.raises(sealed.BackupError):
        sealed.check_ciphertext(c.ciphertext, "0" * 64)
    assert directory_digests(c.snapshot) == c.snapshot_before


@pytest.mark.parametrize(
    "header",
    [
        b"-----BEGIN AGE ENCRYPTED FILE-----\n",
        b"age-encryption.org/v1\n-> scrypt synthetic\n",
        b"age-encryption.org/v1\n-> plugin synthetic\n",
        b"age-encryption.org/v1\n-> X25519MLKEM768 synthetic\n",
    ],
)
def test_password_plugin_pq_and_armor_are_not_classified_as_supported_ciphertext(
    backup_case, header
):
    c = backup_case
    private_file(c.ciphertext, header + b"synthetic-nonstandard-ciphertext" * 4)
    with pytest.raises(sealed.BackupError):
        sealed.check_ciphertext(c.ciphertext, digest(c.ciphertext))


def test_incomplete_snapshot_is_refused_before_native_execution(backup_case, monkeypatch):
    c = backup_case
    (c.snapshot / "automatic.sqlite3").unlink()
    executions = []

    def no_process(*args, **_kwargs):
        executions.append(args)
        raise AssertionError("An incomplete snapshot reached a native process")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    with pytest.raises(sealed.BackupError):
        seal_case(c)
    assert not executions and not c.ciphertext.exists()


def test_native_hash_mismatch_is_rejected_before_any_process(backup_case, monkeypatch):
    c = backup_case
    executions = []

    def no_process(*args, **_kwargs):
        executions.append(args)
        raise AssertionError("Mismatched dependency was executed")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    with pytest.raises(sealed.BackupError):
        sealed.seal(
            c.snapshot,
            c.recipient_file,
            digest(c.recipient_file),
            c.tools.age,
            "0" * 64,
            c.ciphertext,
            confirm_quiescent=True,
        )
    assert not executions and not c.ciphertext.exists()


@pytest.mark.parametrize(
    "recipient",
    [
        b"age-plugin-synthetic1invalid\n",
        b"age1pqsynthetic\n",
        b"password\n",
        b"-----BEGIN AGE ENCRYPTED FILE-----\n",
    ],
)
def test_only_classic_x25519_recipient_is_admitted_before_execution(
    backup_case, monkeypatch, recipient
):
    c = backup_case
    private_file(c.recipient_file, recipient)
    executions = []
    popen = subprocess.Popen

    def only_version(command, *args, **kwargs):
        executions.append(tuple(str(value) for value in command))
        assert command[1:] == ["--version"], "Unapproved recipient reached native encryption"
        return popen(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", only_version)
    with pytest.raises(sealed.BackupError):
        seal_case(c)
    assert all(argv[1:] == ("--version",) for argv in executions)
    assert not c.ciphertext.exists()


@pytest.mark.parametrize("operation", ["seal", "restore"])
def test_existing_destination_is_never_overwritten(backup_case, operation):
    c = backup_case
    if operation == "seal":
        private_file(c.ciphertext, b"owned-by-another-operation")
        with pytest.raises(sealed.BackupError):
            seal_case(c)
        assert c.ciphertext.read_bytes() == b"owned-by-another-operation"
    else:
        seal_case(c)
        output = private_directory(c.root / "occupied")
        private_file(output / "existing", b"owned-by-another-operation")
        with pytest.raises(sealed.BackupError):
            restore_case(c, output)
        assert list(output.iterdir()) == [output / "existing"]
        assert (output / "existing").read_bytes() == b"owned-by-another-operation"


def test_publication_race_preserves_the_other_owners_directory(backup_case, monkeypatch):
    c = backup_case
    seal_case(c)
    output = c.root / "racing-output"
    extract = sealed._extract_archive

    def another_owner_appears(*args, **kwargs):
        result = extract(*args, **kwargs)
        private_directory(output)
        private_file(output / "existing", b"another-operation-owns-this-directory")
        return result

    monkeypatch.setattr(sealed, "_extract_archive", another_owner_appears)
    with pytest.raises(sealed.BackupError):
        restore_case(c, output)
    assert list(output.iterdir()) == [output / "existing"]
    assert (output / "existing").read_bytes() == b"another-operation-owns-this-directory"


def test_hardlinked_identity_never_reaches_extraction(backup_case, monkeypatch):
    c = backup_case
    seal_case(c)
    alias = c.root / "identity-alias"
    os.link(c.identity, alias)
    calls = []

    def never_extract(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Hardlinked identity was admitted")

    monkeypatch.setattr(sealed, "_extract_archive", never_extract)
    with pytest.raises(sealed.BackupError):
        restore_case(c)
    assert not calls and not (c.root / "restored").exists()


def full_configuration(case, *, image="identity_only"):
    root = private_directory(case.root / "configuration")
    private_directory(root / "secrets")
    private_directory(root / "artifacts")
    configuration = {
        "compose.yaml": b"services:\n  observer:\n    image: synthetic.invalid/controller\n",
        "compose.release.yaml": b"services:\n  observer:\n    restart: unless-stopped\n",
        ".env": (f"OPSARK_AI_KEY={INLINE_KEY}\nOPSARK_SSH_KEY=secrets/deployment.key\n").encode(),
        "secrets/inventory.toml": b'[[hosts]]\nid="synthetic-host"\n',
        "secrets/known_hosts": b"synthetic-host synthetic-public-key-only\n",
        "secrets/automation-policy.json": b'{"enabled":false}',
    }
    for name, content in configuration.items():
        private_file(root / name, content)
    private_file(root / "secrets/deployment.key", EXCLUDED_KEY.encode())
    descriptor = {
        "schema_version": 1,
        "compose_files": ["compose.yaml", "compose.release.yaml"],
        "env_files": [".env"],
        "configuration_files": [
            "secrets/inventory.toml",
            "secrets/known_hosts",
            "secrets/automation-policy.json",
        ],
        "unregistered_configuration_sources": False,
        "external_environment_overrides": False,
        "operator_confirmed_configuration_complete": True,
        "credential_files_included": False,
        "remote_root_state_included": False,
        "image": {
            "image_id": "sha256:" + "a" * 64,
            "runtime_sha256": "b" * 64,
            "material": image,
            "archive_sha256": None,
        },
    }
    if image == "embedded_archive":
        material = private_file(root / "artifacts/controller-image.tar", b"synthetic-image-export")
        descriptor["image"]["archive_sha256"] = digest(material)
    private_file(root / "handover.json", json.dumps(descriptor, sort_keys=True).encode())
    return root, configuration, descriptor


def test_full_profile_preserves_raw_known_config_and_does_not_follow_secret_references(
    backup_case, monkeypatch
):
    c = backup_case
    config, expected, _descriptor = full_configuration(c)
    excluded = config / "secrets/deployment.key"
    original_open = Path.open
    held_file = sealed.paths.held_file

    def do_not_read_secret(path, *args, **kwargs):
        assert path.absolute() != excluded.absolute(), "Referenced secret file was opened"
        return original_open(path, *args, **kwargs)

    def do_not_hold_secret(path, *args, **kwargs):
        assert path.absolute() != excluded.absolute(), "Referenced secret file was held"
        return held_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", do_not_read_secret)
    monkeypatch.setattr(sealed.paths, "held_file", do_not_hold_secret)
    result = seal_case(c, profile="observer-handover-v1", config_root=config)
    public_result(result, c.root)
    assert result["profile"] == "observer-handover-v1"
    assert result["image_material_included"] is False
    restore_case(c)
    restored = c.root / "restored/config-original"
    for name, content in expected.items():
        assert (restored / name).read_bytes() == content
    assert not (restored / "secrets/deployment.key").exists()
    assert not list((c.root / "restored").rglob("access-token"))


@pytest.mark.parametrize("image", ["identity_only", "embedded_archive"])
def test_full_profile_preserves_actual_compose_order_and_distinguishes_image_material(
    backup_case, image
):
    c = backup_case
    config, _expected, descriptor = full_configuration(c, image=image)
    descriptor["compose_files"].reverse()
    declared = json.dumps(descriptor, indent=2).encode() + b"\n"
    private_file(config / "handover.json", declared)
    proof = seal_case(c, profile="observer-handover-v1", config_root=config)
    assert proof["image_material_included"] == (image == "embedded_archive")
    restored = restore_case(c)
    public_result(restored, c.root)
    assert restored["image_material_included"] == (image == "embedded_archive")
    assert restored["configuration_activated"] is False and restored["image_loaded"] is False
    assert (c.root / "restored/config-original/handover.json").read_bytes() == declared
    artifact = c.root / "restored/artifacts/controller-image.tar"
    assert artifact.exists() == (image == "embedded_archive")
    if artifact.exists():
        assert digest(artifact) == descriptor["image"]["archive_sha256"]


def test_registered_empty_environment_file_is_preserved_as_an_empty_file(backup_case):
    c = backup_case
    config, _expected, _descriptor = full_configuration(c)
    private_file(config / ".env", b"")
    seal_case(c, profile="observer-handover-v1", config_root=config)
    restore_case(c)
    restored = c.root / "restored/config-original/.env"
    assert restored.is_file() and restored.read_bytes() == b""


@pytest.mark.parametrize(
    "damage",
    ["missing", "unlisted_known", "overrides", "incomplete", "compose_duplicate", "image_hash"],
)
def test_full_profile_never_silently_claims_incomplete_configuration(backup_case, damage):
    c = backup_case
    config, _expected, descriptor = full_configuration(
        c, image="embedded_archive" if damage == "image_hash" else "identity_only"
    )
    if damage == "missing":
        (config / "compose.release.yaml").unlink()
    elif damage == "unlisted_known":
        private_file(config / "observer.env", b"synthetic-unlisted-config=1\n")
    elif damage == "overrides":
        descriptor["external_environment_overrides"] = True
    elif damage == "incomplete":
        descriptor["operator_confirmed_configuration_complete"] = False
    elif damage == "compose_duplicate":
        descriptor["compose_files"].append("compose.yaml")
    else:
        descriptor["image"]["archive_sha256"] = "0" * 64
    private_file(config / "handover.json", json.dumps(descriptor, sort_keys=True).encode())
    with pytest.raises(sealed.BackupError):
        seal_case(c, profile="observer-handover-v1", config_root=config)
    assert not c.ciphertext.exists()


def test_seal_requires_explicit_quiescence_confirmation(backup_case):
    c = backup_case
    with pytest.raises(sealed.BackupError):
        sealed.seal(
            c.snapshot,
            c.recipient_file,
            digest(c.recipient_file),
            c.tools.age,
            c.tools.hashes["age"],
            c.ciphertext,
        )
    assert not c.ciphertext.exists()


def test_cli_stdout_contains_only_ciphertext_summary_not_plaintext(backup_case):
    c = backup_case
    config, _expected, _descriptor = full_configuration(c)
    script = Path(sealed.__file__).resolve()
    out = native(
        [
            sys.executable,
            "-I",
            str(script),
            "seal",
            "--snapshot",
            str(c.snapshot),
            "--recipient-file",
            str(c.recipient_file),
            "--expected-recipient-sha256",
            digest(c.recipient_file),
            "--age-bin",
            str(c.tools.age),
            "--expected-age-sha256",
            c.tools.hashes["age"],
            "--output",
            str(c.ciphertext),
            "--confirm-quiescent",
            "--profile",
            "observer-handover-v1",
            "--config-root",
            str(config),
        ]
    )
    result = json.loads(out)
    public_result(result, c.root)
    assert out.count(b"\n") == 1
    check = native(
        [
            sys.executable,
            "-I",
            str(script),
            "check-ciphertext",
            "--input",
            str(c.ciphertext),
            "--expected-sha256",
            digest(c.ciphertext),
        ]
    )
    public_result(json.loads(check), c.root)
    restored = native(
        [
            sys.executable,
            "-I",
            str(script),
            "restore",
            "--input",
            str(c.ciphertext),
            "--expected-sha256",
            digest(c.ciphertext),
            "--identity-file",
            str(c.identity),
            "--age-bin",
            str(c.tools.age),
            "--expected-age-sha256",
            c.tools.hashes["age"],
            "--age-keygen-bin",
            str(c.tools.keygen),
            "--expected-age-keygen-sha256",
            c.tools.hashes["age-keygen"],
            "--output",
            str(c.root / "cli-restored"),
        ]
    )
    public_result(json.loads(restored), c.root)
    assert (c.root / "cli-restored/config-original/.env").read_bytes() == (
        config / ".env"
    ).read_bytes()


@pytest.mark.parametrize(
    "arguments",
    [
        ["synthetic-unregistered-operation-" + INLINE_KEY],
        ["seal", "--profile", INLINE_KEY],
        ["check-ciphertext", "--unregistered-argument", INLINE_KEY],
    ],
)
def test_invalid_cli_arguments_never_echo_operator_supplied_values(arguments):
    result = subprocess.run(  # noqa: S603 -- current interpreter, fixed local CLI, no shell.
        [sys.executable, "-I", str(Path(sealed.__file__).resolve()), *arguments],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0 and not result.stdout
    assert len(result.stderr) < 200
    assert INLINE_KEY.encode() not in result.stderr
    assert b"Traceback" not in result.stderr
