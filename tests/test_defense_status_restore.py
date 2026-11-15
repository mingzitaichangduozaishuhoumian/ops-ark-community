"""Preserve a scoped defense observation through a detached ten-store recovery."""

import secrets
import shlex
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from test_ssh_defense_status import settings_for
from test_store_transfer import directory_digests, file_digest, transfer

from opsark import main, ssh_defense_status
from opsark.baselines import scope_for
from opsark.config import load_hosts
from opsark.models import CheckResult
from opsark.ssh_defense_status import DefenseObservation, DefenseStatusStore

ACTION = "a" * 32
LIST = "/api/hosts/lab/ssh-defense/actions"
QUERY = f"{LIST}/{ACTION}/status"


def fixture_key(path: Path) -> bytes:
    key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    path.write_bytes(key)
    path.chmod(0o600)
    return key


def test_confirmed_defense_observation_survives_detached_ten_store_restore(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    settings = settings_for(source)
    original_key = fixture_key(source / "key")
    host_public = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    )
    known_hosts = b"[198.18.241.2]:22423 " + host_public + b"\n"
    (source / "known").write_bytes(known_hosts)
    host = load_hosts(settings)["lab"]
    main.create_app(settings)
    observation = DefenseObservation(
        status="active",
        remaining_ms=42_000,
        observed_at=datetime.now(UTC) - timedelta(days=1),
    )
    store = DefenseStatusStore(settings.data_dir / "security.sqlite3")
    assert store.confirm(host, ACTION, observation)
    source_before = {name: file_digest(settings.data_dir / name) for name in transfer.DATABASES}
    backup, rehearsal = tmp_path / "backup", tmp_path / "rehearsal"
    manifest = transfer.snapshot(settings.data_dir, backup)
    assert set(manifest["databases"]) == set(transfer.DATABASES)
    assert (
        manifest["databases"]["security.sqlite3"]["tables"]["ssh_defense_observations"]["rows"] == 1
    )
    backup_before = directory_digests(backup)
    assert transfer.verify_snapshot(backup)["status"] == "complete"
    assert transfer.rehearse(backup, rehearsal)["status"] == "complete"
    assert transfer.verify_snapshot(rehearsal)["status"] == "complete"
    assert all(
        file_digest(settings.data_dir / name) == value for name, value in source_before.items()
    )
    assert directory_digests(backup) == backup_before
    for directory in (backup, rehearsal):
        assert {entry.name for entry in directory.iterdir()} == {
            *transfer.DATABASES,
            "manifest.json",
        }
        assert not any(original_key in entry.read_bytes() for entry in directory.iterdir())
        assert not any(
            settings.token.encode() in entry.read_bytes() for entry in directory.iterdir()
        )

    detached = tmp_path / "detached-credentials"
    detached.mkdir(mode=0o700)
    restored = replace(settings_for(detached), data_dir=rehearsal, token=secrets.token_urlsafe(32))
    replacement_key = fixture_key(detached / "key")
    original_digest, replacement_digest = (
        sha256(original_key).digest(),
        sha256(replacement_key).digest(),
    )
    assert replacement_digest != original_digest
    (detached / "known").write_bytes(known_hosts)
    restored_host = load_hosts(restored)["lab"]
    assert scope_for(restored_host.public) == scope_for(host.public)
    assert restored_host.ssh_defense_action_ids == host.ssh_defense_action_ids == (ACTION,)
    assert (
        DefenseStatusStore(rehearsal / "security.sqlite3").get(restored_host, ACTION) == observation
    )
    calls = []

    def failed_transport(registered, commands, *, output_limit):
        assert registered.key_file == detached / "key"
        assert registered.known_hosts_file == detached / "known"
        assert scope_for(registered.public) == scope_for(host.public)
        assert output_limit == 256 and set(commands) == {ACTION}
        assert shlex.split(commands[ACTION]) == [
            "timeout",
            "-k",
            "1s",
            "5s",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/usr/local/libexec/opsark-defense/deploy/defense/ssh_fixture.py",
            "--profile",
            "private",
            "status-readonly",
            "--action-id",
            ACTION,
        ]
        calls.append(ACTION)
        return {ACTION: CheckResult(name=ACTION, status="timeout", exit_code=None)}

    monkeypatch.setattr(ssh_defense_status, "collect_registered_receipts", failed_transport)
    headers = {"Authorization": "Bearer " + restored.token}
    expected = observation.model_dump(mode="json")
    with TestClient(main.create_app(restored)) as client:
        history = client.get(LIST, headers=headers)
        assert history.status_code == 200
        assert history.json() == {
            "host_id": "lab",
            "actions": [{"action_id": ACTION, "last_observed": expected}],
        }
        assert not calls
        current = client.post(QUERY, headers=headers, json={})
        assert current.status_code == 200
        assert current.json()["status"] == "unavailable"
        assert current.json()["remaining_ms"] is None
        assert current.json()["last_observed"] == expected
        assert client.get(LIST, headers=headers).json() == history.json()
        assert calls == [ACTION]
    assert (
        DefenseStatusStore(rehearsal / "security.sqlite3").get(restored_host, ACTION) == observation
    )
    assert all(
        file_digest(settings.data_dir / name) == value for name, value in source_before.items()
    )
    assert directory_digests(backup) == backup_before
