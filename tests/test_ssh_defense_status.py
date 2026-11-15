"""Keep controller defense reconciliation tied to an enrolled read-only action."""

import json
import shlex
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from opsark import main, ssh_defense_status
from opsark.config import Settings, load_hosts
from opsark.models import CheckResult

_ID = "a" * 32
_TOKEN = "test-ssh-defense-status-token-0123456789"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}
_LIST = "/api/hosts/lab/ssh-defense/actions"
_QUERY = f"{_LIST}/{_ID}/status"


def settings_for(
    tmp_path, *, address="198.18.241.2", port=22423, username="opsark-readonly", ids=None
):
    ids = [_ID] if ids is None else ids
    (tmp_path / "key").touch()
    known_hosts = tmp_path / "known"
    if not known_hosts.exists():
        known_hosts.write_text("synthetic host record\n", encoding="ascii")
    inventory = tmp_path / "inventory.toml"
    inventory.write_text(
        f"""
[credentials.lab]
key_file = "key"
known_hosts_file = "known"
[[hosts]]
id = "lab"
address = "{address}"
port = {port}
username = "{username}"
site_domain = "fixture.invalid"
credential = "lab"
ssh_defense_action_ids = {json.dumps(ids)}
""",
        encoding="ascii",
    )
    return Settings(data_dir=tmp_path / "data", token=_TOKEN, inventory_path=inventory)


def reply(status, remaining, action=_ID):
    return CheckResult(
        name=_ID,
        stdout=json.dumps({"action_id": action, "status": status, "remaining_ms": remaining})
        + "\n",
    )


def test_status_api_keeps_original_observation_across_restart_and_blocks_unenrolled(
    tmp_path, monkeypatch
):
    settings = settings_for(tmp_path)
    frames = [
        reply("active", 42_000),
        None,
        reply("active", 44_000),
        reply("expired", None),
        reply("active", 1_000),
    ]
    calls = []

    def collect(host, commands, *, output_limit):
        assert host.public.id == "lab" and output_limit == 256
        assert set(commands) == {_ID}
        assert shlex.split(commands[_ID]) == [
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
            _ID,
        ]
        calls.append(_ID)
        frame = frames.pop(0)
        return {} if frame is None else {_ID: frame}

    monkeypatch.setattr(ssh_defense_status, "collect_registered_receipts", collect)
    monkeypatch.setattr(main, "explain", lambda *_a, **_k: pytest.fail("status invoked AI"))
    with TestClient(main.create_app(settings)) as client:
        assert client.get(_LIST).status_code == 401
        assert client.post(_QUERY, json={}).status_code == 401
        assert client.post(f"{_LIST}/{'b' * 32}/status", headers=_AUTH, json={}).status_code == 404
        assert client.post(_QUERY, headers=_AUTH, json={"command": "apply"}).status_code == 422
        assert client.get(_LIST, headers=_AUTH).json()["actions"] == [
            {"action_id": _ID, "last_observed": None}
        ]
        assert not calls
        response = client.post(_QUERY, headers=_AUTH, json={})
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        active = response.json()
        assert active["status"] == "active" and active["remaining_ms"] == 42_000
        history = active["last_observed"]
        assert history == {
            "status": "active",
            "remaining_ms": 42_000,
            "observed_at": active["checked_at"],
        }
        assert client.get("/api/reports", headers=_AUTH).json() == []

    with TestClient(main.create_app(settings)) as restarted:
        assert restarted.get(_LIST, headers=_AUTH).json()["actions"] == [
            {"action_id": _ID, "last_observed": history}
        ]
        assert calls == [_ID]
        unavailable = restarted.post(_QUERY, headers=_AUTH, json={}).json()
        assert (unavailable["status"], unavailable["remaining_ms"]) == ("unavailable", None)
        assert unavailable["last_observed"] == history
        stale = restarted.post(_QUERY, headers=_AUTH, json={}).json()
        assert (stale["status"], stale["remaining_ms"], stale["last_observed"]) == (
            "unknown",
            None,
            history,
        )
        expired = restarted.post(_QUERY, headers=_AUTH, json={}).json()
        assert expired["status"] == "expired" and expired["last_observed"]["status"] == "expired"
        contradicted = restarted.post(_QUERY, headers=_AUTH, json={}).json()
        assert contradicted["status"] == "unknown"
        assert contradicted["last_observed"] == expired["last_observed"]
        assert calls == [_ID] * 5

    (tmp_path / "known").write_text("new pinned record\n", encoding="ascii")
    with TestClient(main.create_app(settings)) as repinned:
        assert repinned.get(_LIST, headers=_AUTH).json()["actions"] == [
            {"action_id": _ID, "last_observed": None}
        ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"address": "198.18.241.3"},
        {"port": 22422},
        {"username": "other"},
        {"ids": [_ID, _ID]},
        {"ids": ["A" * 32]},
        {"ids": ["private-input"]},
    ],
)
def test_registration_rejects_scope_or_identity_drift(tmp_path, overrides):
    with pytest.raises(ValueError, match="SSH 防护查询"):
        load_hosts(settings_for(tmp_path, **overrides))


@pytest.mark.parametrize(
    "frame",
    [
        reply("active", True),
        reply("active", 60_001),
        reply("revoked", 5),
        reply("active", 99, "b" * 32),
        reply("active", 90).model_copy(update={"truncated": True}),
        reply("active", 90).model_copy(update={"stderr": "private-output"}),
        reply("active", 90).model_copy(
            update={"stdout": '{"status": "active","status": "revoked"}\n'}
        ),
    ],
)
def test_mismatched_or_unbounded_receipts_never_confirm(frame):
    assert ssh_defense_status._parse(_ID, frame) == ("unavailable", None)


def test_scope_must_match_even_for_internal_command_builder(tmp_path):
    host = load_hosts(settings_for(tmp_path))["lab"]
    invalid = replace(host, public=host.public.model_copy(update={"port": 22}))
    with pytest.raises(ValueError):
        ssh_defense_status.commands_for_defense_status(invalid)
