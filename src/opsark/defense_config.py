"""Deployment-only defense registration; no address, key or permission comes from API input."""

import hashlib
import ipaddress
import json
from pathlib import Path

from opsark.baselines import scope_for
from opsark.config import HostConfig, Settings
from opsark.defense_client import DefenseTarget, RoleCredential, _read_file
from opsark.defense_models import canonical
from opsark.patch_client import USERNAME, PatchTarget


def _keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("防护登记字段不符合固定结构。")


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("防护登记字段不能重复。")
        result[name] = value
    return result


def _path(value):
    if type(value) is not str or not 0 < len(value) <= 1024:
        raise ValueError("防护身份只接受已有文件的绝对路径引用。")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("防护身份只接受已有文件的绝对路径引用。")
    return path


def _address(host: HostConfig) -> str:
    value = ipaddress.ip_address(host.public.address)
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None:
        value = value.ipv4_mapped
    return str(value)


def load_defense_targets(
    settings: Settings,
    hosts: dict[str, HostConfig],
    patch_targets: dict[str, PatchTarget],
) -> dict[str, DefenseTarget]:
    if settings.defense_inventory_path is None:
        return {}
    try:
        raw, seal = _read_file(settings.defense_inventory_path, 16384, private=True)

        def nonfinite(_value):
            raise ValueError("防护登记不能包含非有限数。")

        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=nonfinite)
        _keys(value, ("schema_version", "targets"))
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["targets"]) is not dict
            or not 1 <= len(value["targets"]) <= 10
        ):
            raise ValueError("防护登记版本或目标范围无效。")
        targets = {}
        endpoints = set()
        for host_id, record in value["targets"].items():
            if type(host_id) is not str or host_id not in hosts:
                raise ValueError("防护目标必须来自既有主机登记。")
            _keys(
                record,
                ("root_scope_sha256", "root_policy_sha256", "boot_ref", "binding_ref", "roles"),
            )
            _keys(record["roles"], ("readonly", "observe", "control"))
            host = hosts[host_id]
            address = _address(host)
            if address in endpoints:
                raise ValueError("同一防护监听地址只能登记一个主机身份。")
            endpoints.add(address)
            aliases = [
                item
                for item in hosts.values()
                if item.public.source == "ssh" and _address(item) == address
            ]
            excluded_users = {USERNAME, *(item.public.username for item in aliases)}
            credentials = []
            for name in ("readonly", "observe", "control"):
                role = record["roles"][name]
                _keys(role, ("username", "key_file", "known_hosts_file", "trusted_hosts_digest"))
                if role["username"] in excluded_users:
                    raise ValueError("防护身份必须独立于采集与补丁身份。")
                credentials.append(
                    RoleCredential(
                        role["username"],
                        22423,
                        _path(role["key_file"]),
                        _path(role["known_hosts_file"]),
                        role["trusted_hosts_digest"],
                    )
                )
            # DefenseTarget also checks copies of the same key at different paths.
            excluded = tuple(
                dict.fromkeys(
                    [item.key_file for item in aliases]
                    + [
                        target.key_file
                        for target in patch_targets.values()
                        if _address(target.host) == address
                    ]
                )
            )
            targets[host_id] = DefenseTarget(
                host,
                *credentials,
                record["root_scope_sha256"],
                record["root_policy_sha256"],
                record["boot_ref"],
                record["binding_ref"],
                excluded,
            )
        _, current = _read_file(settings.defense_inventory_path, 16384, private=True)
        if current != seal:
            raise ValueError("防护登记在加载期间已改变。")
        return targets
    except Exception:
        raise ValueError("防护登记、独立身份或可信范围未能核实。") from None


def defense_registry_scope(targets: dict[str, DefenseTarget]) -> str | None:
    if not targets:
        return None
    value = {}
    for host_id, target in sorted(targets.items()):
        if type(target) is not DefenseTarget or host_id != target.host.public.id:
            raise ValueError("防护登记与主机身份不一致。")
        value[host_id] = {
            "host_scope": scope_for(target.host.public),
            "root_scope": target.root_scope_sha256,
            "policy": target.root_policy_sha256,
            "boot": target.boot_ref,
            "binding": target.binding_ref,
            "roles": {
                role: {
                    "username": credential.username,
                    "port": credential.port,
                    "key_identity": credential.key_identity,
                    "host_pin_digest": credential.trusted_hosts_digest,
                }
                for role in ("readonly", "observe", "control")
                if (credential := getattr(target, role))
            },
        }
    return hashlib.sha256(canonical(value)).hexdigest()
