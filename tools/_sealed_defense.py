"""Inert, stdlib-only v2 handover validation; never open a referenced credential.

This is a deliberately narrow archive contract, not an application loader or a
Compose interpreter. Unknown configuration needs a future reviewed contract.
"""

import base64
import hashlib
import ipaddress
import json
import re
import struct
import tomllib
from datetime import datetime, timedelta
from pathlib import PurePosixPath

PROFILE = "observer-handover-v2"
INVENTORY = "secrets/defense-targets.json"
POLICY = "secrets/defense-policy.json"
OVERLAY = "compose.defense.yaml"
ROLES = ("readonly", "observe", "control")
PINS = {role: f"secrets/defense-{role}-known_hosts" for role in ROLES}
CONFIGS = {INVENTORY, POLICY, OVERLAY, *PINS.values()}
TEMPLATE_HASHES = {
    "compose.yaml": "3e948c89012154337d6300bad88bf40d3e220eea5ad557d0412c0bec0142ac96",
    "compose.lab.yaml": "2c544065e18f0a1628b1013dbe575e023a48b65775ce95fe294e330bf695f35f",
}
POLICY_SHA = hashlib.sha256(
    b"opsark-defense-requests/v1;private;198.18.241.0/28;target=.2:22422;"
    b"sources=.3,.5;management=.4;arm=120s;ttl=60000ms;ports=5;"
    b"success=deny;capacity=8;single-element;no-retry-after-intent"
).hexdigest()
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
ALIASES = {"fixture-a", "fixture-b"}


def require(value, code="v2_configuration_refused"):
    if not value:
        raise ValueError(code)


def keys(value, allowed, required=()):
    require(type(value) is dict and set(required) <= set(value) <= set(allowed))


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum)


def boolean(value):
    require(type(value) is bool)


def digest(value):
    require(type(value) is str and HEX.fullmatch(value) is not None)


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None)


def timestamp(value):
    require(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value)
    )
    return datetime.fromisoformat(value[:-1] + "+00:00")


def text(raw, maximum=1024 * 1024):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = raw.decode("utf-8")
    require("\x00" not in value and not any(ord(c) < 32 and c not in "\r\n\t" for c in value))
    require(
        not any(
            marker in value.upper()
            for marker in (
                "PRIVATE KEY",
                "AGE-SECRET-KEY-",
                "BEARER ",
                "-----BEGIN",
                "PASSWORD=",
                "TOKEN=",
            )
        ),
        "v2_inline_secret_refused",
    )
    return value


def document(raw, maximum=16384):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result)
            result[name] = value
        return result

    def invalid(_):
        raise ValueError("v2_configuration_refused")

    return json.loads(text(raw, maximum), object_pairs_hook=unique, parse_constant=invalid)


def registration(value):
    if value is None:
        return set()
    keys(
        value,
        {"inventory_file", "policy_file", "role_known_hosts_files", "compose_file"},
        {"inventory_file", "policy_file", "role_known_hosts_files", "compose_file"},
    )
    require(
        value["inventory_file"] == INVENTORY
        and value["policy_file"] == POLICY
        and value["compose_file"] == OVERLAY
        and value["role_known_hosts_files"] == PINS
    )
    return set(CONFIGS)


def inventory(raw):
    # Legacy inventory bytes may contain inline configuration secrets. They stay
    # inside the local encrypted handover. Inspect only identity/reference fields
    # needed to bind the newly registered defense records; never load a key.
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024)
    value = tomllib.loads(raw.decode("utf-8"))
    credentials = value["credentials"]
    require(type(credentials) is dict and 1 <= len(credentials) <= 10)
    for name, entry in credentials.items():
        require(ID.fullmatch(name))
        require(type(entry) is dict)
        for field in ("key_file", "known_hosts_file"):
            require(type(entry.get(field)) is str and 0 < len(entry[field]) <= 1024)
    require(type(value["hosts"]) is list and 1 <= len(value["hosts"]) <= 10)
    hosts, addresses = {}, set()
    for host in value["hosts"]:
        require(type(host) is dict)
        require(type(host["id"]) is str and ID.fullmatch(host["id"]) and host["id"] not in hosts)
        require(
            type(host["username"]) is str
            and USER.fullmatch(host["username"])
            and host["username"] != "root"
        )
        require(type(host["credential"]) is str and host["credential"] in credentials)
        require(type(host["address"]) is str)
        address = ipaddress.ip_address(host["address"])
        address = (
            address.ipv4_mapped
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
            else address
        )
        require(str(address) not in addresses)
        addresses.add(str(address))
        require(
            type(host["site_domain"]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host["site_domain"])
        )
        integer(host.get("port", 22), 1, 65535)
        integer(host.get("expected_upstream_port", 8081), 1, 65535)
        hosts[host["id"]] = {**host, "address": str(address)}
    return hosts, credentials


def public_pins(raw):
    value = text(raw, 65536)
    found = {}
    for line in value.splitlines():
        require(bool(line) and len(line) <= 512)
        fields = line.split()
        require(len(fields) == 3 and fields[1] == "ssh-ed25519")
        match = re.fullmatch(r"\[([^\[\]]+)\]:([0-9]{1,5})", fields[0])
        address = str(ipaddress.ip_address(match[1] if match else fields[0]))
        port = int(match[2]) if match else 22
        integer(port, 1, 65535)
        key = base64.b64decode(fields[2], validate=True)
        require(
            len(key) == 51
            and key[:19] == struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
        )
        require((address, port) not in found and len(found) < 20)
        found[address, port] = hashlib.sha256(key).hexdigest()
    require(bool(found))
    return found


def registry(raw, hosts, pins):
    value = document(raw)
    keys(value, {"schema_version", "targets"}, {"schema_version", "targets"})
    integer(value["schema_version"], 1, 1)
    targets = value["targets"]
    require(type(targets) is dict and 1 <= len(targets) <= 10 and set(targets) <= set(hosts))
    parsed_pins = {role: public_pins(raw) for role, raw in pins.items()}
    expected_pins = {(hosts[host_id]["address"], 22423) for host_id in targets}
    require(all(set(rows) == expected_pins for rows in parsed_pins.values()))
    require(all(parsed_pins[role] == parsed_pins[ROLES[0]] for role in ROLES))
    for host_id, record in targets.items():
        keys(
            record,
            {"root_scope_sha256", "root_policy_sha256", "boot_ref", "binding_ref", "roles"},
            {"root_scope_sha256", "root_policy_sha256", "boot_ref", "binding_ref", "roles"},
        )
        for name in ("root_scope_sha256", "root_policy_sha256", "boot_ref", "binding_ref"):
            digest(record[name])
        require(record["root_policy_sha256"] == POLICY_SHA)
        keys(record["roles"], ROLES, ROLES)
        for role, entry in record["roles"].items():
            keys(
                entry,
                {"username", "key_file", "known_hosts_file", "trusted_hosts_digest"},
                {"username", "key_file", "known_hosts_file", "trusted_hosts_digest"},
            )
            require(entry["username"] == "opsark-defense-" + role)
            require(entry["username"] != hosts[host_id]["username"])
            require(entry["key_file"] == f"/run/opsark/defense-{role}.key")
            require(entry["known_hosts_file"] == "/run/opsark/" + PurePosixPath(PINS[role]).name)
            require(entry["trusted_hosts_digest"] == hashlib.sha256(pins[role]).hexdigest())
            require((hosts[host_id]["address"], 22423) in parsed_pins[role])
    return targets


def grant(value, targets, *, execution=False):
    base = {
        "v",
        "enabled",
        "grant_ref",
        "issued_at",
        "expires_at",
        "host_ids",
        "target_scope_sha256",
        "target_policy_sha256",
        "windows",
    }
    extra = (
        {
            "root_grant_refs",
            "boot_refs",
            "binding_refs",
            "wire_revisions",
            "source_aliases",
            "max_actions_per_day",
            "max_total_actions",
        }
        if execution
        else set()
    )
    keys(value, base | extra, (base - {"v", "enabled"}) | extra)
    integer(value.get("v", 1), 1, 1)
    boolean(value.get("enabled", False))
    identifier(value["grant_ref"])
    require(
        timedelta(0)
        < timestamp(value["expires_at"]) - timestamp(value["issued_at"])
        <= timedelta(hours=24)
    )
    ids = value["host_ids"]
    require(
        type(ids) is list
        and 1 <= len(ids) <= 10
        and all(type(i) is str for i in ids)
        and len(ids) == len(set(ids))
        and set(ids) <= set(targets)
    )
    maps = {
        "target_scope_sha256": "root_scope_sha256",
        "target_policy_sha256": "root_policy_sha256",
    }
    if execution:
        maps |= {"boot_refs": "boot_ref", "binding_refs": "binding_ref"}
        keys(value["root_grant_refs"], ids, ids)
        for item in value["root_grant_refs"].values():
            identifier(item)
        revisions = value["wire_revisions"]
        require(type(revisions) is list and 1 <= len(revisions) <= 8)
        for revision in revisions:
            integer(revision, 1, 2**31 - 1)
        require(len(revisions) == len(set(revisions)))
        aliases = value["source_aliases"]
        require(
            type(aliases) is list
            and 1 <= len(aliases) <= 2
            and all(type(i) is str for i in aliases)
            and set(aliases) <= ALIASES
            and len(aliases) == len(set(aliases))
        )
        integer(value["max_actions_per_day"], 1, 8)
        integer(value["max_total_actions"], value["max_actions_per_day"], 8)
    for field, target_field in maps.items():
        keys(value[field], ids, ids)
        require(all(value[field][i] == targets[i][target_field] for i in ids))
    windows = value["windows"]
    require(type(windows) is list and 1 <= len(windows) <= 7)
    for window in windows:
        keys(
            window,
            {"weekdays", "start_minute", "end_minute"},
            {"weekdays", "start_minute", "end_minute"},
        )
        days = window["weekdays"]
        require(type(days) is list and 1 <= len(days) <= 7)
        for day in days:
            integer(day, 0, 6)
        require(len(days) == len(set(days)))
        integer(window["start_minute"], 0, 1439)
        integer(window["end_minute"], window["start_minute"] + 1, 1440)


def policy(raw, targets):
    value = document(raw)
    keys(
        value,
        {
            "v",
            "enabled",
            "profile",
            "action",
            "ttl_ms",
            "source_aliases",
            "observation",
            "execution",
            "ai",
        },
    )
    integer(value.get("v", 1), 1, 1)
    boolean(value.get("enabled", False))
    require(
        value.get("profile", "private-198.18.241.0/28") == "private-198.18.241.0/28"
        and value.get("action", "block-single-source") == "block-single-source"
        and value.get("source_aliases", ["fixture-a", "fixture-b"]) == ["fixture-a", "fixture-b"]
    )
    integer(value.get("ttl_ms", 60000), 60000, 60000)
    for name in ("observation", "execution"):
        if value.get(name) is not None:
            grant(value[name], targets, execution=name == "execution")
    ai = value.get("ai", {})
    keys(
        ai,
        {
            "enabled",
            "provider_fingerprint",
            "max_analyses_per_day",
            "max_total_analyses",
            "requires_ai",
        },
    )
    boolean(ai.get("enabled", False))
    boolean(ai.get("requires_ai", False))
    integer(ai.get("max_analyses_per_day", 1), 1, 8)
    integer(ai.get("max_total_analyses", 1), 1, 8)
    if ai.get("provider_fingerprint") is not None:
        digest(ai["provider_fingerprint"])
    require(not ai.get("enabled", False) or ai.get("provider_fingerprint") is not None)


def validate_bundle(plan, documents):
    """Validate provided bytes only. No filesystem, process, network or secret loader."""
    require(type(plan) is dict and plan.get("schema_version") == 2)
    added = registration(plan.get("ssh_defense"))
    names = {
        "handover.json",
        *plan["compose_files"],
        *plan["env_files"],
        *plan["configuration_files"],
    }
    require(set(documents) == names and (set(documents) & CONFIGS) == added)
    require(document(documents["handover.json"], 65536) == plan)
    for name, expected in TEMPLATE_HASHES.items():
        if name in documents:
            require(
                hashlib.sha256(documents[name].replace(b"\r\n", b"\n")).hexdigest() == expected,
                "v2_compose_template_refused",
            )
    require(
        document(documents["compose.release.yaml"])
        == {"services": {"observer": {"image": plan["image"]["image_id"]}}},
        "v2_release_overlay_refused",
    )
    hosts, credentials = inventory(documents["secrets/inventory.toml"])
    # Existing env/collector-pin/APT configuration keeps the v1 raw-byte
    # contract. It is not interpreted, executed, sanitized, or model input.
    if added:
        require(
            document(documents[OVERLAY])
            == {
                "services": {
                    "observer": {
                        "environment": {
                            "OPSARK_DEFENSE_INVENTORY": "/run/opsark/defense-targets.json",
                            "OPSARK_DEFENSE_POLICY": "/run/opsark/defense-policy.json",
                            "OPSARK_DEFENSE_WORKER_ENABLED": "false",
                        }
                    }
                }
            },
            "v2_defense_overlay_refused",
        )
        targets = registry(documents[INVENTORY], hosts, {r: documents[p] for r, p in PINS.items()})
        excluded = {entry["key_file"] for entry in credentials.values()}
        require(not excluded & {f"/run/opsark/defense-{r}.key" for r in ROLES})
        policy(documents[POLICY], targets)
