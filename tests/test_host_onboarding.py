"""Synthetic public host pins and a round trip through the real inventory parser."""

import base64
import hashlib
import socket
import tomllib
from pathlib import Path

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from opsark.config import Settings, load_hosts
from opsark.host_onboarding import (
    HostOnboardingError,
    HostOnboardingRequest,
    prepare_host_onboarding,
)

_PRIVATE_MARKER = "synthetic-comment-not-for-output"


@pytest.fixture(scope="module")
def key() -> paramiko.PKey:
    private = Ed25519PrivateKey.generate()
    message = paramiko.Message()
    message.add_string("ssh-ed25519")
    message.add_string(private.public_key().public_bytes_raw())
    return paramiko.Ed25519Key(data=message.asbytes())


def _pubkey(key: paramiko.PKey) -> str:
    return f"{key.get_name()} {key.get_base64()}"


@pytest.fixture
def request_body(key):
    return {
        "host_id": "www.production-01",
        "name": ' 客户站 "预览" \\ 一号 ',
        "address": "192.0.2.18",
        "site_domain": "www.example.test",
        "container_name": "website-api",
        "host_key": f"{_pubkey(key)} {_PRIVATE_MARKER}\r\n",
        "expected_fingerprint": key.fingerprint,
    }


@pytest.mark.parametrize(
    "address,port,normalized,endpoint",
    [
        ("192.0.2.18", 22, "192.0.2.18", "192.0.2.18"),
        ("192.0.2.18", 2222, "192.0.2.18", "[192.0.2.18]:2222"),
        ("2001:0DB8:0000:0:0:0:0:12", 22, "2001:db8::12", "2001:db8::12"),
        ("2001:0DB8:0000:0:0:0:0:12", 2222, "2001:db8::12", "[2001:db8::12]:2222"),
    ],
)
def test_exact_pin_inventory_and_newline_digests(
    key, request_body, tmp_path, address, port, normalized, endpoint
):
    body = HostOnboardingRequest(**(request_body | {"address": address, "port": port}))
    preview = prepare_host_onboarding(body)
    line = f"{endpoint} {_pubkey(key)}"
    assert preview.known_hosts == line + "\n"
    assert preview.address == normalized and preview.port == port
    assert preview.fingerprint == key.fingerprint
    assert _PRIVATE_MARKER not in preview.model_dump_json()
    assert set(preview.model_dump()) == {
        "host_id",
        "address",
        "port",
        "fingerprint",
        "known_hosts",
        "inventory",
        "key_file",
        "known_hosts_file",
        "known_hosts_digests",
    }
    files = {
        "lf": (line + "\n").encode(),
        "crlf": (line + "\r\n").encode(),
        "no_final_newline": line.encode(),
    }
    assert preview.known_hosts_digests == {
        name: hashlib.sha256(content).hexdigest() for name, content in files.items()
    }
    parsed = tomllib.loads(preview.inventory)
    assert parsed["hosts"][0]["credential"] == "readonly-www.production-01"
    assert parsed["hosts"][0]["name"] == body.name.strip()
    assert parsed["hosts"][0]["expected_upstream_port"] == 8081
    assert parsed["hosts"][0]["username"] == "opsark-readonly"
    assert "health_checks" not in parsed["hosts"][0]
    assert Path(preview.key_file).parent.as_posix() == "ssh"
    assert Path(preview.known_hosts_file).parent.as_posix() == "ssh"

    inventory = tmp_path / "opsark.local.toml"
    inventory.write_text(preview.inventory, encoding="utf-8")
    (tmp_path / "ssh").mkdir()
    key_path = tmp_path / preview.key_file
    key_path.write_bytes(b"synthetic placeholder; configuration only checks file existence")
    known_path = tmp_path / preview.known_hosts_file
    settings = Settings(data_dir=tmp_path, inventory_path=inventory, token="fixture-token-" * 3)
    for variant, content in files.items():
        known_path.write_bytes(content)
        host = load_hosts(settings)[body.host_id]
        assert host.key_file == key_path and host.known_hosts_file == known_path
        assert host.public.address == normalized and host.public.port == port
        assert host.public.name == body.name.strip()
        assert host.public.trusted_hosts_digest == preview.known_hosts_digests[variant]
        host_keys = paramiko.HostKeys(str(known_path))
        assert host_keys.check(endpoint, key)


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa"])
def test_other_public_algorithms_are_parsed(key_type, request_body):
    key = paramiko.RSAKey.generate(2048) if key_type == "rsa" else paramiko.ECDSAKey.generate()
    body = HostOnboardingRequest(
        **(request_body | {"host_key": _pubkey(key), "expected_fingerprint": key.fingerprint})
    )
    assert prepare_host_onboarding(body).known_hosts == f"192.0.2.18 {_pubkey(key)}\n"


@pytest.mark.parametrize(
    "invalid_key",
    [
        "private",
        "known_hosts",
        "multiple_lines",
        "invalid_base64",
        "noncanonical_padding",
        "mismatched_algorithm",
        "trailing_bytes",
        "incomplete_blob",
    ],
)
def test_malformed_public_keys_are_rejected_without_reflecting_input(
    key, request_body, invalid_key
):
    public = _pubkey(key)
    invalid = {
        "private": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_PRIVATE_MARKER}\n-----END KEY-----",
        "known_hosts": f"192.0.2.18 {public} {_PRIVATE_MARKER}",
        "multiple_lines": f"{public} {_PRIVATE_MARKER}\n{public}\n",
        "invalid_base64": f"ssh-ed25519 $%@ {_PRIVATE_MARKER}",
        "noncanonical_padding": f"{public}= {_PRIVATE_MARKER}",
        "mismatched_algorithm": f"ssh-rsa {key.get_base64()} {_PRIVATE_MARKER}",
        "trailing_bytes": "ssh-ed25519 " + base64.b64encode(key.asbytes() + b"x").decode(),
        "incomplete_blob": "ssh-ed25519 " + base64.b64encode(key.asbytes()[:-1]).decode(),
    }
    body = HostOnboardingRequest(**(request_body | {"host_key": invalid[invalid_key]}))
    with pytest.raises(HostOnboardingError, match="公开主机密钥") as failure:
        prepare_host_onboarding(body)
    assert _PRIVATE_MARKER not in str(failure.value) and public not in str(failure.value)


def test_fingerprint_must_be_independently_supplied_and_matches(key, request_body):
    different = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    with pytest.raises(HostOnboardingError, match="预期指纹不一致") as failure:
        prepare_host_onboarding(
            HostOnboardingRequest(**(request_body | {"expected_fingerprint": different}))
        )
    assert different not in str(failure.value) and key.fingerprint not in str(failure.value)
    request_body.pop("expected_fingerprint")
    with pytest.raises(ValidationError):
        HostOnboardingRequest(**request_body)


def test_invalid_rsa_parameters_are_rejected_with_static_error(request_body):
    message = paramiko.Message()
    message.add_string("ssh-rsa")
    message.add_mpint(-65537)
    message.add_mpint(123456789)
    key = "ssh-rsa " + base64.b64encode(message.asbytes()).decode()
    body = HostOnboardingRequest(**(request_body | {"host_key": key}))
    with pytest.raises(HostOnboardingError, match="公开主机密钥") as failure:
        prepare_host_onboarding(body)
    assert key not in str(failure.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("address", "host.example.test"),
        ("address", "192.0.2.18,192.0.2.19"),
        ("address", "fe80::1%eth0"),
        ("username", "root"),
        ("site_domain", "https://example.test"),
        ("host_id", "../outside"),
        ("container_name", "-option"),
        ("name", "multi\nline"),
        ("name", "bad\u202ename"),
    ],
)
def test_invalid_inventory_metadata_stops_preview(request_body, field, value):
    body = HostOnboardingRequest(**(request_body | {field: value}))
    with pytest.raises(HostOnboardingError):
        prepare_host_onboarding(body)


@pytest.mark.parametrize(
    "extra",
    [
        {"port": "22"},
        {"port": True},
        {"port": 0},
        {"expected_upstream_port": 65536},
        {"host_key": "x" * 8193},
        {"key_file": "caller-supplied-path"},
    ],
)
def test_request_is_strict_and_cannot_choose_paths(request_body, extra):
    with pytest.raises(ValidationError):
        HostOnboardingRequest(**(request_body | extra))


def test_preview_is_stateless_and_never_connects(request_body, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("an onboarding preview must not connect or open files")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", forbidden)
        patched.setattr(socket, "create_connection", forbidden)
        patched.setattr(paramiko, "SSHClient", forbidden)
        body = HostOnboardingRequest(**request_body)
        assert prepare_host_onboarding(body) == prepare_host_onboarding(body)
