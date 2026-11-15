"""Exercise the richer syntax runner without using Docker or host configuration."""

import importlib
import io
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

IMAGE = "sha256:" + "a" * 64


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.import_module("deploy.nginx.fixture_context_syntax")


@pytest.mark.parametrize("name", ["ORIGINAL", "CANDIDATE"])
def test_supported_target_is_sent_as_stdin_with_only_fixed_tmpfs(module, monkeypatch, name):
    data = getattr(module.fixture_action, name)

    def check(stdin, image, *, validator, extra_tmpfs):
        assert stdin == data
        assert image == IMAGE
        assert repr(data) not in validator
        assert [mount.split(":", 1)[0] for mount in extra_tmpfs] == [
            "/fixture-runtime",
            "/fixture-sites",
            "/run/opsark-nginx-live",
        ]
        assert all("nosuid,nodev,noexec" in mount for mount in extra_tmpfs)
        return "passed"

    monkeypatch.setattr(module.config_snapshot, "_docker_syntax", check)
    assert module.validate(data, IMAGE) == "passed"


@pytest.mark.parametrize("data", [b"", b"x" * 1025, b"include /etc/nginx/nginx.conf;\n"])
def test_unsupported_target_never_enters_docker(module, monkeypatch, data):
    def unexpected(*_args, **_kwargs):
        pytest.fail("unsupported target reached Docker")

    monkeypatch.setattr(module.config_snapshot, "_docker_syntax", unexpected)
    assert module.validate(data, IMAGE) == "unsupported"


@pytest.mark.parametrize(("native_result", "exit_code"), [(0, 0), (1, 10), (None, 11)])
def test_child_reconstructs_exact_graph_and_checks_real_wrapper(
    module, monkeypatch, tmp_path, native_result, exit_code
):
    for mount in ("fixture-runtime", "fixture-sites", "run/opsark-nginx-live"):
        (tmp_path / mount).mkdir(parents=True)

    def mapped(path):
        return tmp_path / path.lstrip("/")

    def nginx(args, **kwargs):
        assert args == [
            "/usr/sbin/nginx",
            "-t",
            "-q",
            "-e",
            "stderr",
            "-p",
            "/run/opsark-nginx-live",
            "-c",
            str(tmp_path / "fixture-runtime/nginx.conf"),
        ]
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 5
        for name, content in module.fixture_context.FIXTURE_FILES.items():
            assert (tmp_path / "fixture-runtime" / name).read_bytes() == content
        target = tmp_path / "fixture-sites" / module.fixture_action.TARGET_NAME
        assert target.read_bytes() == module.fixture_action.CANDIDATE
        if native_result is None:
            raise OSError("simulated unavailable binary")
        return SimpleNamespace(returncode=native_result)

    monkeypatch.setattr(subprocess, "run", nginx)
    monkeypatch.setattr(
        sys, "stdin", SimpleNamespace(buffer=io.BytesIO(module.fixture_action.CANDIDATE))
    )
    monkeypatch.setattr(os, "umask", lambda _: 0o077)
    # Substitute only the Path constructor so the fixed child can run in a test directory.
    program = module._program().replace("from pathlib import Path", "")
    with pytest.raises(SystemExit) as stopped:
        exec(compile(program, "<reviewed fixture child>", "exec"), {"Path": mapped})  # noqa: S102
    assert stopped.value.code == exit_code


@pytest.mark.parametrize(
    ("recheck_matches", "expected"), [(True, "passed"), (False, "unavailable")]
)
def test_tls_requires_and_rechecks_sealed_context(
    module, monkeypatch, tmp_path, recheck_matches, expected
):
    tls_directory = tmp_path / "tls"
    metadata = {"dev": 1, "ino": 2}
    tls = module.fixture_context.TLSMaterial("a" * 64, metadata, metadata, metadata)
    contexts = iter(
        [
            SimpleNamespace(tls=tls, tls_chain=None, fingerprint="b" * 64),
            SimpleNamespace(
                tls=tls, tls_chain=None, fingerprint="b" * 64 if recheck_matches else "c" * 64
            ),
        ]
    )
    policy = SimpleNamespace(anchor=tmp_path)
    workspaces = []

    def fixture_policy(workspace):
        workspaces.append(workspace)
        return policy

    def verify_context(actual):
        assert actual is policy
        return next(contexts)

    def check(stdin, image, *, validator, extra_tmpfs, tls_directory):
        assert stdin == module.fixture_action.CANDIDATE
        assert image == IMAGE
        assert tls_directory == tmp_path / "tls"
        assert repr(stdin) not in validator
        assert "ssl_certificate /fixture-tls/cert.pem" in validator
        assert "ssl_certificate_key /fixture-tls/key.pem" in validator
        assert all(not mount.startswith("/fixture-tls:") for mount in extra_tmpfs)
        return "passed"

    monkeypatch.setattr(module.fixture_action, "fixture_policy", fixture_policy)
    monkeypatch.setattr(module.fixture_context, "verify_context", verify_context)
    monkeypatch.setattr(module.config_snapshot, "_docker_syntax", check)
    assert (
        module.validate(module.fixture_action.CANDIDATE, IMAGE, tls_directory=tls_directory)
        == expected
    )
    assert workspaces == [tmp_path, tmp_path]


def test_tls_without_sealed_material_never_enters_docker(module, monkeypatch, tmp_path):
    def unexpected(*_args, **_kwargs):
        pytest.fail("unsealed TLS source reached Docker")

    monkeypatch.setattr(
        module.fixture_action, "fixture_policy", lambda anchor: SimpleNamespace(anchor=anchor)
    )
    monkeypatch.setattr(
        module.fixture_context,
        "verify_context",
        lambda policy: SimpleNamespace(tls=None, tls_chain=None),
    )
    monkeypatch.setattr(module.config_snapshot, "_docker_syntax", unexpected)
    assert (
        module.validate(module.fixture_action.CANDIDATE, IMAGE, tls_directory=tmp_path / "tls")
        == "unavailable"
    )


@pytest.mark.parametrize(
    ("change", "native_calls", "exit_code"),
    [("none", 1, 0), ("before", 0, 11), ("after", 1, 11)],
)
def test_tls_child_checks_mounted_identities_without_opening_key(
    module, monkeypatch, tmp_path, change, native_calls, exit_code
):
    for mount in ("fixture-runtime", "fixture-sites", "run/opsark-nginx-live", "fixture-tls"):
        (tmp_path / mount).mkdir(parents=True)
    certificate = tmp_path / "fixture-tls/cert.pem"
    key = tmp_path / "fixture-tls/key.pem"
    certificate.write_bytes(b"synthetic-public-certificate")
    key.write_bytes(b"synthetic-private-key-canary")
    tls = module.fixture_context.TLSMaterial(
        "a" * 64,
        module.config_snapshot._signature(certificate.stat()),
        module.config_snapshot._signature(key.stat()),
        module.config_snapshot._signature(key.parent.stat()),
    )
    program = module._program(tls).replace("from pathlib import Path", "")
    assert "synthetic-private-key-canary" not in program
    calls = []

    def nginx(args, **kwargs):
        calls.append(args)
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        if change == "after":
            key.write_bytes(b"changed-synthetic-key")
        return SimpleNamespace(returncode=0)

    original_open = Path.open

    def no_tls_read(path, mode="r", *args, **kwargs):
        assert path not in (key, certificate) or "w" in mode
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_tls_read)
    monkeypatch.setattr(subprocess, "run", nginx)
    monkeypatch.setattr(
        sys, "stdin", SimpleNamespace(buffer=io.BytesIO(module.fixture_action.CANDIDATE))
    )
    monkeypatch.setattr(os, "umask", lambda _: 0o077)
    if change == "before":
        key.write_bytes(b"changed-synthetic-key")
    with pytest.raises(SystemExit) as stopped:
        exec(  # noqa: S102 -- reviewed fixed child with only its test Path constructor substituted.
            compile(program, "<reviewed TLS fixture child>", "exec"),
            {"Path": lambda path: tmp_path / path.lstrip("/")},
        )
    assert stopped.value.code == exit_code
    assert len(calls) == native_calls


@pytest.mark.parametrize("rotate", [False, True])
def test_chain_validation_selects_sealed_graph_and_rechecks_after_native(
    module, monkeypatch, tmp_path, rotate
):
    directory = tmp_path / "tls"
    material = SimpleNamespace(
        directory={"dev": 1, "ino": 2},
        files={
            name: {"dev": 1, "ino": number}
            for number, name in enumerate(
                [
                    "root.pem",
                    *[
                        f"{site}-{part}.pem"
                        for site in ("target", "control", "default")
                        for part in ("chain", "key")
                    ],
                ],
                start=3,
            )
        },
    )
    old = SimpleNamespace(tls=None, tls_chain=material, fingerprint="b" * 64)
    current = SimpleNamespace(tls=None, tls_chain=material, fingerprint="c" * 64) if rotate else old
    contexts = iter([old, current])
    monkeypatch.setattr(module, "_tls_context", lambda path: next(contexts))

    def native(stdin, image, *, validator, extra_tmpfs, tls_directory):
        assert stdin == module.fixture_action.CANDIDATE
        assert image == IMAGE and tls_directory == directory
        assert repr(stdin) not in validator
        for filename in material.files:
            assert f"/fixture-tls/{filename}" in validator
        for site in ("target", "control", "default"):
            assert f"ssl_certificate /fixture-tls/{site}-chain.pem;" in validator
        assert all(not mount.startswith("/fixture-tls:") for mount in extra_tmpfs)
        return "passed"

    monkeypatch.setattr(module.config_snapshot, "_docker_syntax", native)
    assert module.validate(module.fixture_action.CANDIDATE, IMAGE, tls_directory=directory) == (
        "unavailable" if rotate else "passed"
    )


@pytest.mark.parametrize("change", ["none", "before", "after"])
def test_chain_child_checks_all_mounted_material_without_opening_keys(
    module, monkeypatch, tmp_path, change
):
    for mount in ("fixture-runtime", "fixture-sites", "run/opsark-nginx-live", "fixture-tls"):
        (tmp_path / mount).mkdir(parents=True)
    directory = tmp_path / "fixture-tls"
    files = [directory / "root.pem"]
    for site in ("target", "control", "default"):
        files.extend(directory / f"{site}-{kind}.pem" for kind in ("chain", "key"))
    for path in files:
        path.write_bytes(b"synthetic-material-canary")
    chain = SimpleNamespace(
        directory=module.config_snapshot._signature(directory.stat()),
        files={path.name: module.config_snapshot._signature(path.stat()) for path in files},
    )
    program = module._program(tls_chain=chain).replace("from pathlib import Path", "")
    assert "synthetic-material-canary" not in program
    calls = []

    def native(args, **kwargs):
        calls.append(args)
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        for name, content in module.fixture_context.CHAIN_FIXTURE_FILES.items():
            assert (tmp_path / "fixture-runtime" / name).read_bytes() == content
        if change == "after":
            (directory / "control-key.pem").write_bytes(b"changed-synthetic-key")
        return SimpleNamespace(returncode=0)

    original_open = Path.open

    def guard(path, mode="r", *args, **kwargs):
        assert path not in files or "w" in mode
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard)
    monkeypatch.setattr(subprocess, "run", native)
    monkeypatch.setattr(
        sys, "stdin", SimpleNamespace(buffer=io.BytesIO(module.fixture_action.CANDIDATE))
    )
    monkeypatch.setattr(os, "umask", lambda _: 0o077)
    if change == "before":
        (directory / "default-chain.pem").write_bytes(b"changed-synthetic-chain")
    with pytest.raises(SystemExit) as stopped:
        exec(  # noqa: S102 -- fixed child code with only test Path mapping.
            compile(program, "<reviewed chain fixture child>", "exec"),
            {"Path": lambda path: tmp_path / path.lstrip("/")},
        )
    assert stopped.value.code == (0 if change == "none" else 11)
    assert len(calls) == int(change != "before")
