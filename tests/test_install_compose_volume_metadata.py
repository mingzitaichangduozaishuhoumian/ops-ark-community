"""Exercise reviewed imports and narrowly recoverable Compose volume installation."""

import hashlib
import json
import shlex
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.readonly import compose_volume_metadata as helper
from deploy.readonly import install_compose_volume_metadata as installer

STAGE = Path(installer.__file__).resolve().parent
SCOPE = helper.canonical({"schema_version": 1, "compose_project": "synthetic"})
HELPER = (STAGE / "compose_volume_metadata.py").read_bytes()


@pytest.fixture
def fake(tmp_path, monkeypatch):
    paths = {key: tmp_path / key.lower() for key in ("TARGET", "SCOPE", "MARKER", "POLICY")}
    approved = tmp_path / "approved"
    command = "LC_ALL=C timeout -k 1s 5s " + shlex.quote(str(paths["TARGET"]))
    for key, path in paths.items():
        monkeypatch.setattr(installer, key, path)
    monkeypatch.setattr(installer, "COMMAND", command)
    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    files = {
        approved: SCOPE,
        paths["POLICY"]: helper.canonical(
            {
                "schema_version": 1,
                "commands": {
                    command: ["timeout", "-k", "1s", "5s", str(paths["TARGET"])],
                },
            }
        ),
        STAGE / "compose_volume_metadata.py": HELPER,
        STAGE / "guard.py": (STAGE / "guard.py").read_bytes(),
    }
    modes = {}
    writes = []

    def record(path, raw, mode, _tools):
        files[path] = raw
        modes[path] = mode
        writes.append(path)

    def installed(path, mode, _limit, _tools):
        if path in files:
            installer.need(modes[path] == mode)
        return files.get(path)

    def reviewed(source, name, raw):
        result = original_reviewed(source, name, raw)
        if source.name == "guard.py":
            result.load_policy = lambda path: result.parse_policy(files[path])
        return result

    original_reviewed = installer.reviewed
    monkeypatch.setattr(
        installer,
        "filesystem_tools",
        lambda _: SimpleNamespace(read_root=lambda path, _limit: files[path]),
    )
    monkeypatch.setattr(installer, "installation_slot", lambda *_: nullcontext())
    monkeypatch.setattr(installer, "installed_bytes", installed)
    monkeypatch.setattr(installer, "write_verified", record)
    monkeypatch.setattr(installer, "reviewed", reviewed)
    return SimpleNamespace(
        paths=paths,
        approved=approved,
        files=files,
        modes=modes,
        writes=writes,
        command=command,
        record=record,
    )


def run(fake, expected=None):
    return installer.install(STAGE, fake.approved, expected or installer.digest(SCOPE))


def test_writes_only_registered_helper_scope_and_marker(fake):
    p = fake.paths
    old_policy = fake.files[p["POLICY"]]
    evidence = run(fake)
    assert fake.writes == [p["MARKER"], p["TARGET"], p["SCOPE"], p["MARKER"]]
    assert fake.files[p["POLICY"]] == old_policy
    assert fake.files[p["TARGET"]] == HELPER and fake.files[p["SCOPE"]] == SCOPE
    assert fake.modes == {p["MARKER"]: 0o600, p["SCOPE"]: 0o600, p["TARGET"]: 0o755}
    assert json.loads(fake.files[p["MARKER"]]) == {
        "schema": installer.SCHEMA,
        "helper_sha256": installer.digest(HELPER),
        "scope_sha256": installer.digest(SCOPE),
    }
    assert evidence["permissions_expanded"] is evidence["ssh_restarted"] is False


@pytest.mark.parametrize(
    "case", ["no_command", "wrong_argv", "scope_hash", "uncanonical", "foreign"]
)
def test_refuses_unenrolled_or_untrusted_initial_state_without_writes(fake, case):
    expected = installer.digest(SCOPE)
    if case == "no_command":
        fake.files[fake.paths["POLICY"]] = b'{"schema_version":1,"commands":{}}'
    elif case == "wrong_argv":
        doc = json.loads(fake.files[fake.paths["POLICY"]])
        doc["commands"][fake.command].append("--unexpected")
        fake.files[fake.paths["POLICY"]] = helper.canonical(doc)
    elif case == "scope_hash":
        expected = "0" * 64
    elif case == "uncanonical":
        raw = b'{"schema_version":1,"compose_project":"synthetic"}\n'
        fake.files[fake.approved] = raw
        expected = installer.digest(raw)
    else:
        fake.files[fake.paths["TARGET"]] = HELPER
        fake.modes[fake.paths["TARGET"]] = 0o755
    with pytest.raises(ValueError):
        run(fake, expected)
    assert fake.writes == []


@pytest.mark.parametrize("failure_at", ["TARGET", "SCOPE", "FINAL"])
def test_resume_exact_interrupted_pair_only(fake, monkeypatch, failure_at):
    p = fake.paths
    original = fake.record

    def interrupted(path, raw, mode, tools):
        if path == p.get(failure_at) or (
            failure_at == "FINAL" and path == p["MARKER"] and b"pending_helper" not in raw
        ):
            raise OSError("synthetic interruption")
        original(path, raw, mode, tools)

    monkeypatch.setattr(installer, "write_verified", interrupted)
    with pytest.raises(OSError, match="synthetic interruption"):
        run(fake)
    pending = fake.files[p["MARKER"]]
    assert b"pending_helper_sha256" in pending
    new_scope = helper.canonical({"schema_version": 1, "compose_project": "changed"})
    fake.files[fake.approved] = new_scope
    with pytest.raises(ValueError):
        run(fake, installer.digest(new_scope))
    assert fake.files[p["MARKER"]] == pending
    fake.files[fake.approved] = SCOPE
    monkeypatch.setattr(installer, "write_verified", original)
    assert run(fake)["installed"] is True
    assert b"pending_helper_sha256" not in fake.files[p["MARKER"]]


@pytest.mark.parametrize("case", ["modified", "missing", "mixed_pending", "duplicate"])
def test_refuses_drift_and_unproducible_marker_pairs(fake, case):
    p = fake.paths
    run(fake)
    fake.writes.clear()
    if case == "modified":
        fake.files[p["TARGET"]] = b"synthetic foreign bytes"
    elif case == "missing":
        del fake.files[p["SCOPE"]]
    elif case == "mixed_pending":
        fake.files[p["MARKER"]] = helper.canonical(
            {
                "schema": installer.SCHEMA,
                "helper_sha256": "a" * 64,
                "scope_sha256": "b" * 64,
                "pending_helper_sha256": installer.digest(HELPER),
                "pending_scope_sha256": installer.digest(SCOPE),
            }
        )
        fake.files[p["TARGET"]] = b"synthetic old helper"
        doc = json.loads(fake.files[p["MARKER"]])
        doc["helper_sha256"] = hashlib.sha256(fake.files[p["TARGET"]]).hexdigest()
        fake.files[p["MARKER"]] = helper.canonical(doc)
    else:
        fake.files[p["MARKER"]] = fake.files[p["MARKER"]].replace(
            b'"schema":', b'"schema":"duplicate","schema":'
        )
    with pytest.raises(ValueError):
        run(fake)
    assert fake.writes == []
