"""Exercise the optional installer through its reviewed imports and pinned outputs."""

import shlex
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.readonly import compose_generation as helper
from deploy.readonly import install_compose_generation as installer
from deploy.readonly import install_compose_volume_metadata as shared

STAGE = Path(installer.__file__).resolve().parent
SCOPE = helper.canonical(
    {
        "schema_version": 1,
        "compose_project": "synthetic",
        "container_name": "synthetic.web",
        "service": "web",
    }
)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    files = {}
    writes = []
    paths = {key: tmp_path / key.lower() for key in ("POLICY", "TARGET", "SCOPE", "MARKER", "KEY")}
    command = "LC_ALL=C timeout -k 1s 5s " + shlex.quote(str(paths["TARGET"]))
    args = ["timeout", "-k", "1s", "5s", str(paths["TARGET"])]
    for key, path in paths.items():
        monkeypatch.setattr(installer, key, path)
    monkeypatch.setattr(installer, "COMMAND", command)
    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    approved = tmp_path / "approved"
    files[approved] = SCOPE
    files[paths["POLICY"]] = helper.canonical({"schema_version": 1, "commands": {command: args}})
    files[STAGE / "compose_generation.py"] = (STAGE / "compose_generation.py").read_bytes()
    files[STAGE / "guard.py"] = (STAGE / "guard.py").read_bytes()
    paths["KEY"].write_bytes(bytes(range(32)))
    key_identity = helper.identity(paths["KEY"].lstat())

    def write(path, raw, mode, _tools):
        files[path] = raw
        writes.append((path, mode))

    def reviewed(path, name, raw):
        module = real_reviewed(path, name, raw)
        if path.name == "guard.py":
            module.load_policy = lambda key: module.parse_policy(files[key])
        if path.name == "compose_generation.py":
            module.read_private = lambda *_: (bytes(range(32)), key_identity)
        return module

    real_reviewed = shared.reviewed
    monkeypatch.setattr(installer, "load_shared", lambda _: shared)
    monkeypatch.setattr(
        shared, "filesystem_tools", lambda _: SimpleNamespace(read_root=lambda path, _: files[path])
    )
    monkeypatch.setattr(shared, "reviewed", reviewed)
    monkeypatch.setattr(shared, "installation_slot", lambda *_: nullcontext())
    monkeypatch.setattr(shared, "installed_bytes", lambda path, *_: files.get(path))
    monkeypatch.setattr(shared, "write_verified", write)
    return SimpleNamespace(paths=paths, files=files, writes=writes, approved=approved)


def install(layout):
    return installer.install(STAGE, layout.approved, installer.digest(SCOPE))


def test_exact_files_and_private_key_untouched(layout):
    p = layout.paths
    old_policy = layout.files[p["POLICY"]]
    result = install(layout)
    assert layout.writes == [
        (p["MARKER"], 0o600),
        (p["TARGET"], 0o755),
        (p["SCOPE"], 0o600),
        (p["MARKER"], 0o600),
    ]
    assert layout.files[p["POLICY"]] == old_policy
    assert p["KEY"].read_bytes() == bytes(range(32))
    assert result == {
        "installed": True,
        "helper_sha256": installer.digest(layout.files[STAGE / "compose_generation.py"]),
        "scope_sha256": installer.digest(SCOPE),
    }


def test_policy_and_drift_refused_before_writes(layout):
    p = layout.paths
    policy = layout.files[p["POLICY"]]
    layout.files[p["POLICY"]] = helper.canonical({"schema_version": 1, "commands": {}})
    with pytest.raises(ValueError):
        install(layout)
    layout.files[p["POLICY"]] = policy
    layout.files[p["TARGET"]] = b"unrelated"
    with pytest.raises(ValueError):
        install(layout)
    assert not layout.writes
