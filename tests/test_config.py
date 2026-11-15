from pathlib import Path

import pytest

from opsark.config import Settings, load_hosts, load_settings, validate_ai_url


def test_generated_token_persists_without_being_part_of_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    for variable in ("OPSARK_TOKEN", "OPSARK_AI_BASE_URL", "OPSARK_AI_KEY", "OPSARK_AI_MODEL"):
        monkeypatch.delenv(variable, raising=False)
    first = load_settings()
    second = load_settings()
    assert first.token == second.token
    assert len(first.token) >= 32
    assert (tmp_path / "access-token").is_file()


def test_scheduled_vulnerability_scan_is_disabled_without_explicit_configuration(tmp_path):
    settings = Settings(data_dir=tmp_path, token="test")
    assert settings.vulnerability_scan_enabled is False
    assert settings.vulnerability_scan_host_ids == ()
    assert settings.vulnerability_scan_interval_seconds == 3600


@pytest.mark.parametrize(
    "update",
    [
        {"vulnerability_scan_enabled": "true"},
        {"vulnerability_scan_enabled": True},
        {"vulnerability_scan_host_ids": ["host"]},
        {"vulnerability_scan_host_ids": ("host", "host")},
        {"vulnerability_scan_host_ids": ("../host",)},
        {"vulnerability_scan_interval_seconds": 299},
        {"vulnerability_scan_interval_seconds": 86401},
        {"vulnerability_scan_interval_seconds": True},
    ],
)
def test_scheduled_scan_configuration_rejects_implicit_or_unbounded_scope(tmp_path, update):
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, token="test", **update)


def test_scheduled_scan_settings_load_from_explicit_deployment_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OPSARK_VULNERABILITY_SCAN_ENABLED", "true")
    monkeypatch.setenv("OPSARK_VULNERABILITY_SCAN_HOSTS", "host-one, host-two")
    monkeypatch.setenv("OPSARK_VULNERABILITY_SCAN_INTERVAL", "3600")
    settings = load_settings()
    assert settings.vulnerability_scan_enabled is True
    assert settings.vulnerability_scan_host_ids == ("host-one", "host-two")
    assert settings.vulnerability_scan_interval_seconds == 3600


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/v1",
        "https://u:p@example.com",
        "file:///tmp/a",
        "https://example.com/v1?token=secret",
    ],
)
def test_provider_url_rejects_insecure_or_credentialed_addresses(url):
    with pytest.raises(ValueError):
        validate_ai_url(url)


def test_loopback_provider_and_https_allowed():
    assert validate_ai_url("http://127.0.0.1:11434/v1/") == "http://127.0.0.1:11434/v1"
    assert validate_ai_url("https://provider.example/v1") == "https://provider.example/v1"


def write_inventory(tmp_path: Path, **fields) -> Settings:
    (tmp_path / "key").write_text("test-key-reference", encoding="utf-8")
    (tmp_path / "known").write_text("test-known-reference", encoding="utf-8")
    record = {
        "id": "web-01",
        "name": "Website",
        "address": "192.0.2.10",
        "site_domain": "example.com",
        "username": "opsark-readonly",
        "credential": "test",
        "container_name": "api",
        **fields,
    }
    lines = ["[credentials.test]", 'key_file="key"', 'known_hosts_file="known"', "[[hosts]]"]
    lines.extend(f'{key}="{value}"' for key, value in record.items())
    inventory = tmp_path / "inventory.toml"
    inventory.write_text("\n".join(lines), encoding="utf-8")
    return Settings(data_dir=tmp_path, token="test-token-value-" * 3, inventory_path=inventory)


def test_inventory_only_publishes_target_metadata(tmp_path):
    settings = write_inventory(tmp_path)
    hosts = load_hosts(settings)
    assert hosts["web-01"].public.source == "ssh"
    assert "key_file" not in hosts["web-01"].public.model_dump()
    assert hosts["web-01"].key_file == (tmp_path / "key").resolve()


@pytest.mark.parametrize(
    "fields",
    [
        {"container_name": "api; echo unsafe"},
        {"username": "root"},
        {"address": "host; command"},
        {"address": "ssh.example.com"},
        {"id": "../host"},
    ],
)
def test_inventory_rejects_unbounded_targets_and_command_injection(tmp_path, fields):
    settings = write_inventory(tmp_path, **fields)
    with pytest.raises(ValueError):
        load_hosts(settings)


def test_unconfigured_inventory_is_empty(tmp_path):
    assert load_hosts(Settings(data_dir=tmp_path, token="test")) == {}


def test_declared_site_checks_and_target_identity_are_loaded(tmp_path):
    settings = write_inventory(tmp_path)
    with settings.inventory_path.open("a", encoding="utf-8") as handle:
        handle.write('\nnginx_config_path="/etc/nginx/conf.d/shop.conf"\n')
        handle.write('[[hosts.health_checks]]\nid="shop"\ndomain="shop.example.com"\n')
        handle.write('path="/healthz"\nexpected_body="ok"\nread_only_confirmed=true\n')
    public = load_hosts(settings)["web-01"].public
    assert public.health_checks[0].read_only_confirmed is True
    assert public.nginx_config_path == "/etc/nginx/conf.d/shop.conf"
    assert len(public.trusted_hosts_digest) == 64


@pytest.mark.parametrize("domain", ["shop..example.com", "bad-.example.com"])
def test_invalid_registered_domain_fails_before_ssh_collection(tmp_path, domain):
    settings = write_inventory(tmp_path)
    with settings.inventory_path.open("a", encoding="utf-8") as handle:
        handle.write(f'\n[[hosts.health_checks]]\nid="shop"\ndomain="{domain}"\n')
    with pytest.raises(ValueError):
        load_hosts(settings)


def test_site_checks_are_not_implicitly_authorized(tmp_path):
    settings = write_inventory(tmp_path)
    with settings.inventory_path.open("a", encoding="utf-8") as handle:
        handle.write('\n[[hosts.health_checks]]\nid="shop"\ndomain="shop.example.com"\n')
    assert not load_hosts(settings)["web-01"].public.health_checks[0].read_only_confirmed
