"""Deployment registration/install contracts with synthetic paths and public source."""

import hashlib
import importlib.util
import json
import shlex
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_compose_discovery_api import TOKEN, _inventory
from test_nginx_dependencies import scope

from deploy.readonly import install_nginx_dependencies as installer
from deploy.readonly import nginx_dependencies as helper
from opsark.collector import nginx_dependencies_command
from opsark.config import Settings, load_hosts


def test_inventory_scope_and_exact_policy_export_never_open_private_key(tmp_path, monkeypatch):
    inventory = _inventory(tmp_path, "demo")
    inventory.write_text(
        inventory.read_text() + 'nginx_dependency_scope_digest = "' + helper.digest(scope()) + '"\n'
    )
    original = Path.open

    def checked(path, *args, **kwargs):
        assert path != tmp_path / "key", "Private reference must not be read"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked)
    target = load_hosts(Settings(data_dir=tmp_path, token=TOKEN, inventory_path=inventory))[
        "fixture"
    ]
    assert target.nginx_scope_digest == helper.digest(scope())
    assert "nginx_dependency_scope_digest" not in target.public.model_dump()
    file = Path(__file__).parents[1] / "deploy/readonly/export_policy.py"
    spec = importlib.util.spec_from_file_location("nginx_policy_export", file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "fixed-policy.json"
    module.export_policy(inventory, "fixture", output)
    commands = json.loads(output.read_text())["commands"]
    exact = "LC_ALL=C " + nginx_dependencies_command(target)
    assert commands[exact] == shlex.split(exact.removeprefix("LC_ALL=C "))
    assert not any("nginx -T" in command or "nginx -s" in command for command in commands)


@pytest.mark.parametrize("value", [True, 1, ["a" * 64], "g" * 64, "a" * 63, "a" * 64 + ";id"])
def test_controller_registration_rejects_untyped_or_arbitrary_scope(tmp_path, value):
    inventory = _inventory(tmp_path, "demo")
    inventory.write_text(
        inventory.read_text() + "nginx_dependency_scope_digest = " + json.dumps(value) + "\n"
    )
    with pytest.raises(ValueError, match="Nginx"):
        load_hosts(Settings(data_dir=tmp_path, token=TOKEN, inventory_path=inventory))


@pytest.mark.parametrize(
    "change",
    [
        {"extra": True},
        {"entry": "/etc/passwd"},
        {"include_roots": ["/etc/nginx/../secrets"]},
        {"include_roots": [{"unknown": True}]},
        {"compose_project": "demo;id"},
        {"schema_version": True},
    ],
)
def test_target_scope_is_closed_and_cannot_escape_nginx(change):
    value = json.loads(scope()) | change
    with pytest.raises(helper.Refused, match="scope_invalid"):
        helper.checked_scope(helper.canonical(value))


@pytest.mark.parametrize(
    "uid,mode,directory",
    [
        (10001, stat.S_IFREG | 0o644, False),
        (0, stat.S_IFREG | 0o664, False),
        (0, stat.S_IFLNK | 0o777, False),
        (0, stat.S_IFDIR | 0o777, True),
    ],
)
def test_helper_rejects_writable_foreign_or_symlink_metadata(uid, mode, directory):
    path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_uid=uid, st_mode=mode, st_nlink=1))
    with pytest.raises(helper.Refused, match="path_untrusted"):
        helper.trusted(path, directory=directory)


def test_read_identity_excludes_only_atime_not_content_or_permissions():
    values = dict(
        st_dev=1,
        st_ino=2,
        st_mode=stat.S_IFREG | 0o644,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_size=20,
        st_mtime_ns=4,
        st_ctime_ns=5,
        st_atime_ns=6,
    )
    before = SimpleNamespace(**values)
    assert helper.identity(before) == helper.identity(
        SimpleNamespace(**(values | {"st_atime_ns": 9}))
    )
    for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode"):
        assert helper.identity(before) != helper.identity(SimpleNamespace(**(values | {field: 99})))


@pytest.mark.parametrize(
    "variant", ["fresh", "resume", "foreign", "drifted", "unregistered_command", "scope_hash"]
)
def test_fixed_installer_only_adopts_owned_hashes_and_exact_command(
    tmp_path, monkeypatch, capsys, variant
):
    paths = {
        "TARGET": tmp_path / "public-helper",
        "SCOPE": tmp_path / "scope",
        "MARKER": tmp_path / "marker",
        "POLICY": tmp_path / "policy",
    }
    for key, path in paths.items():
        monkeypatch.setattr(installer, key, path)
    raw_scope = scope()
    public_helper = (Path(helper.__file__)).read_bytes()
    root_input = tmp_path / "administrator-scope"
    values = {
        root_input: raw_scope,
        paths["POLICY"]: helper.canonical(
            {"commands": {installer.COMMAND: ["timeout", "-k", "1s", "5s", str(paths["TARGET"])]}}
        ),
    }
    if variant == "unregistered_command":
        values[paths["POLICY"]] = b'{"commands":{}}'
    if variant in {"resume", "foreign", "drifted"}:
        paths["TARGET"].write_text("synthetic public old helper")
        values[paths["TARGET"]] = b"synthetic public old helper"
        if variant != "foreign":
            paths["MARKER"].write_text("synthetic marker placeholder")
            values[paths["MARKER"]] = helper.canonical(
                {
                    "helper_sha256": "0" * 64,
                    "scope_sha256": None,
                    "pending_helper_sha256": hashlib.sha256(values[paths["TARGET"]]).hexdigest()
                    if variant == "resume"
                    else "1" * 64,
                    "pending_scope_sha256": helper.digest(raw_scope),
                }
            )
    writes = []
    monkeypatch.setattr(
        installer,
        "read_root",
        lambda path, _limit: values.get(path, public_helper),
    )
    monkeypatch.setattr(
        installer, "write_root", lambda path, raw, mode: writes.append((path, raw, mode))
    )
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "install",
            "--scope",
            str(root_input),
            "--expected-sha256",
            "0" * 64 if variant == "scope_hash" else helper.digest(raw_scope),
        ],
    )
    if variant in {"fresh", "resume"}:
        installer.main()
        assert {path for path, _, _ in writes} == {paths["TARGET"], paths["SCOPE"], paths["MARKER"]}
        assert len(writes) == 4
        assert all(
            mode == (0o755 if path == paths["TARGET"] else 0o600) for path, _, mode in writes
        )
        assert json.loads(capsys.readouterr().out)["permissions_expanded"] is False
    else:
        with pytest.raises(ValueError):
            installer.main()
        assert writes == []
