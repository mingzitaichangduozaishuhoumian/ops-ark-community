"""APT transaction validation is pure and fail closed before any package install."""

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

HOOK_PATH = Path(__file__).resolve().parents[1] / "deploy/vulnerability/transaction_hook.py"
spec = importlib.util.spec_from_file_location("patch_transaction_hook", HOOK_PATH)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

JOB = "a" * 32
ARCHIVE = "/var/cache/apt/archives/curl_8.5.0-2ubuntu10.6_amd64.deb"
PAYLOAD = b"a verified archive fixture, not an installable package"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def action(**changes):
    return {
        "package": "curl",
        "old_version": "8.5.0-2ubuntu10.5",
        "old_arch": "amd64",
        "old_multiarch": "none",
        "direction": "<",
        "new_version": "8.5.0-2ubuntu10.6",
        "new_arch": "amd64",
        "new_multiarch": "none",
        "action": "unpack",
        "deb_path": ARCHIVE,
        "sha256": DIGEST,
    } | changes


def configure(**changes):
    return action(**({"action": "configure", "deb_path": None, "sha256": None} | changes))


def expected(*actions, **changes):
    return json.dumps(
        {"schema_version": 1, "job_id": JOB, "actions": list(actions)} | changes
    ).encode()


def protocol(*actions, version="3", config=("APT::Architecture=amd64",)):
    lines = ["VERSION " + version, *config, ""]
    for value in actions:
        operation = (
            value["deb_path"]
            if value["action"] == "unpack"
            else {
                "configure": "**CONFIGURE**",
                "remove": "**REMOVE**",
            }[value["action"]]
        )
        lines.append(" ".join([*(value[field] for field in hook.FIELDS[:8]), operation]))
    return ("\n".join(lines) + "\n").encode()


def test_complete_upgrade_matches_in_any_order_and_normalizes_legacy_multiarch():
    plan = hook.parse_expected(expected(action(), configure()), JOB)
    observed = hook.parse_protocol(
        protocol(configure(old_multiarch="no"), action(new_multiarch="no"))
    )
    calls = []

    def hasher(path):
        calls.append(path)
        return DIGEST

    receipt_digest = hook.verify_transaction(plan, observed, hasher)
    assert len(receipt_digest) == 64
    assert calls == [ARCHIVE]
    assert hook.verify_transaction(plan, list(reversed(observed)), hasher) == receipt_digest


@pytest.mark.parametrize("version", ["1", "2", "4", "03", "3 "])
def test_protocol_downgrade_or_unknown_version_is_never_accepted(version):
    with pytest.raises(hook.HookError, match="VERSION 3"):
        hook.parse_protocol(protocol(action(), version=version))


@pytest.mark.parametrize(
    "data",
    [
        b"VERSION 3\nAPT::Architecture=amd64\n",
        b"VERSION 3\nMalformed-config\n\n",
        b"VERSION 3\n\n",
        b"VERSION 3\r\n\r\n",
        b"VERSION 3\nAPT::x=a\vb=c\n\n",
        b"VERSION 3\n\n\xff\n",
        b"VERSION 3\n\npackage - - none < 1 amd64 none **ERROR**\n",
        protocol(action()).rstrip(b"\n"),
        protocol(action()).replace(b"curl ", b"curl  ", 1),
        b"x" * (hook.MAX_PROTOCOL_BYTES + 1),
    ],
    ids=lambda data: hashlib.sha256(data).hexdigest()[:8],
)
def test_malformed_or_unbounded_protocol_is_rejected(data):
    with pytest.raises(hook.HookError):
        hook.parse_protocol(data)


@pytest.mark.parametrize(
    "changes",
    [
        {"package": "openssl"},
        {"old_version": "8.5.0-2ubuntu10.4"},
        {"new_version": "8.5.0-2ubuntu10.7"},
        {"old_arch": "arm64"},
        {"new_arch": "arm64"},
        {"new_multiarch": "foreign"},
        {"direction": ">"},
        {"deb_path": "/var/cache/apt/archives/another.deb"},
    ],
)
def test_any_package_version_architecture_direction_or_filename_drift_blocks_before_read(changes):
    plan = hook.parse_expected(expected(action(), configure()), JOB)
    observed = hook.parse_protocol(protocol(action(**changes), configure()))
    calls = []
    with pytest.raises(hook.HookError, match="differs"):
        hook.verify_transaction(plan, observed, lambda path: calls.append(path))
    assert calls == []


def test_missing_configure_extra_package_duplicate_and_empty_actions_are_rejected():
    plan = hook.parse_expected(expected(action(), configure()), JOB)
    for data in (
        protocol(action()),
        protocol(action(), configure(), configure(package="unplanned")),
        protocol(action(), configure(), configure()),
        protocol(),
    ):
        with pytest.raises(hook.HookError):
            hook.verify_transaction(plan, hook.parse_protocol(data), lambda _path: DIGEST)


def test_archive_content_must_match_the_approved_sha256():
    plan = hook.parse_expected(expected(action()), JOB)
    with pytest.raises(hook.HookError, match="SHA256"):
        hook.verify_transaction(
            plan, hook.parse_protocol(protocol(action())), lambda _path: "0" * 64
        )


@pytest.mark.parametrize("job", ["", "a" * 31, "A" * 32, "../" + "a" * 32, "a" * 32 + "\n"])
def test_job_identifier_is_exactly_lowercase_hex(job):
    with pytest.raises(hook.HookError):
        hook.parse_expected(expected(action()), job)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"job_id": "b" * 32},
        {"command": "apt-get upgrade"},
        {"actions": []},
        {"actions": [action()] * (hook.MAX_ACTIONS + 1)},
        {"actions": [action(), action()]},
    ],
)
def test_expected_schema_identity_and_action_budget_are_strict(changes):
    with pytest.raises(hook.HookError):
        hook.parse_expected(expected(action(), **changes), JOB)


def test_duplicate_json_fields_bad_encoding_and_oversized_plan_are_rejected():
    for data in (
        expected(action()).replace(b'"package": "curl"', b'"package":"curl","package":"openssl"'),
        b"\xff",
        b" " * (hook.MAX_EXPECTED_BYTES + 1),
    ):
        with pytest.raises(hook.HookError):
            hook.parse_expected(data, JOB)


@pytest.mark.parametrize(
    "changes",
    [
        {"sha256": None},
        {"sha256": "0" * 63},
        {"command": "touch /tmp/unexpected"},
        {"package": "curl;whoami"},
        {"old_version": "1\n2"},
        {"old_arch": "-"},
        {"new_multiarch": "unknown"},
        {"direction": "="},
        {"deb_path": "relative.deb"},
        {"deb_path": "/etc/unexpected.deb"},
        {"deb_path": "/var/cache/apt/archives/../escape.deb"},
        {"deb_path": "/var/cache/apt/archives//extra.deb"},
        {"deb_path": "/var/cache/apt/archives/$(id).deb"},
        {"action": "remove"},
        {"action": "configure"},
    ],
)
def test_invalid_package_metadata_archives_and_shell_fields_are_rejected(changes):
    with pytest.raises(hook.HookError):
        hook.parse_expected(expected(action(**changes)), JOB)


def test_own_private_archive_directory_is_bound_to_the_job():
    path = "/var/lib/opsark-patch/jobs/" + JOB + "/archives/curl.deb"
    assert (
        hook.parse_expected(expected(action(deb_path=path)), JOB)["actions"][0]["deb_path"] == path
    )
    with pytest.raises(hook.HookError):
        hook.parse_expected(expected(action(deb_path=path.replace(JOB, "b" * 32))), JOB)


def test_configure_and_explicit_removal_cannot_smuggle_archive_values():
    removal = action(
        action="remove",
        new_version="-",
        new_arch="-",
        new_multiarch="none",
        direction=">",
        deb_path=None,
        sha256=None,
    )
    plan = hook.parse_expected(expected(removal), JOB)
    hook.verify_transaction(
        plan,
        hook.parse_protocol(protocol(removal)),
        lambda _path: pytest.fail("Removal must not read an archive"),
    )
    with pytest.raises(hook.HookError):
        hook.parse_expected(expected(configure(sha256=DIGEST)), JOB)


def test_metadata_rejects_wrong_owner_writable_files_symlinks_and_hardlinks():
    base = {"st_uid": 0, "st_mode": stat.S_IFREG | 0o600, "st_nlink": 1}
    assert hook._metadata_ok(SimpleNamespace(**base), private=True)
    for change in (
        {"st_uid": 1000},
        {"st_mode": stat.S_IFREG | 0o622},
        {"st_mode": stat.S_IFREG | 0o644},
        {"st_nlink": 2},
        {"st_mode": stat.S_IFLNK | 0o600},
        {"st_mode": stat.S_IFIFO | 0o600},
    ):
        assert not hook._metadata_ok(SimpleNamespace(**(base | change)), private=True)
    assert hook._metadata_ok(
        SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755), directory=True
    )
    assert not hook._metadata_ok(
        SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755), directory=True, private=True
    )


def test_real_archive_read_hash_and_size_budget_without_requiring_root(tmp_path, monkeypatch):
    archive = tmp_path / "archive.deb"
    archive.write_bytes(PAYLOAD)
    # Filesystem trust is tested independently; isolate this real bounded read.
    monkeypatch.setattr(hook, "_open_file", lambda path, **_options: os.open(path, os.O_RDONLY))
    assert hook.archive_sha256(archive) == DIGEST
    with pytest.raises(hook.HookError, match="size budget"):
        hook._read_trusted(archive, len(PAYLOAD) - 1)
    assert hook._read_trusted(archive, len(PAYLOAD)) == PAYLOAD


def test_mutating_an_open_archive_during_hash_is_rejected(tmp_path, monkeypatch):
    archive = tmp_path / "archive.deb"
    archive.write_bytes(PAYLOAD)
    monkeypatch.setattr(hook, "_open_file", lambda path, **_options: os.open(path, os.O_RDONLY))
    real_read = os.read
    changed = False

    def read(descriptor, maximum):
        nonlocal changed
        data = real_read(descriptor, maximum)
        if data and not changed:
            changed = True
            archive.write_bytes(PAYLOAD + b"changed")
        return data

    monkeypatch.setattr(hook.os, "read", read)
    with pytest.raises(hook.HookError, match="changed"):
        hook.archive_sha256(archive)


@pytest.mark.skipif(os.name != "posix", reason="Atomic dirfd receipt requires POSIX")
def test_receipt_is_atomic_private_and_binds_expected_and_transaction(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hook,
        "_open_directory",
        lambda *_args, **_options: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    hook.write_receipt(JOB, "b" * 64, "c" * 64)
    path = tmp_path / "hook-passed.json"
    receipt = json.loads(path.read_bytes())
    assert receipt["job_id"] == JOB
    assert receipt["expected_sha256"] == "b" * 64
    assert receipt["transaction_sha256"] == "c" * 64
    assert receipt["checked_at"].endswith("+00:00")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [path]


def test_invalid_cli_invocation_never_echoes_untrusted_input_or_executes(tmp_path):
    value = "../../do-not-execute;echo-private-sentinel"
    result = subprocess.run(  # noqa: S603 -- fixed interpreter and script; hostile value is data.
        [sys.executable, str(HOOK_PATH), value],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "private-sentinel" not in result.stderr
    assert "dpkg must not start" in result.stderr
