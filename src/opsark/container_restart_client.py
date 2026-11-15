"""Pinned fixed-command SSH for the dedicated single-container restart role."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, cast

from opsark.defense_client import _read_file
from opsark.nginx_action_client import (
    DIGEST,
    NginxActionTarget,
    _host_address,
    _invoke_fixed,
    _nonfinite,
    _unique,
    canonical,
)

COMMAND = "opsark-container-restart-v1"
USERNAME = "opsark-container-restart"
FIELDS = {
    "prepare": {"plan_id", "mode_revision"},
    "plan_status": {"plan_id"},
    "submit": {"plan_id", "action_id", "plan_digest", "approval_id", "mode_revision"},
    "status": {"action_id"},
    "reconcile_status": {"action_id", "plan_id", "plan_digest", "mode_revision"},
    "observe": {"action_id"},
}


@dataclass(frozen=True, repr=False)
class ContainerRestartTarget(NginxActionTarget):
    username: ClassVar[str] = USERNAME
    container_id: str = ""

    def __post_init__(self):
        if (
            not self.host.container_binding_confirmed
            or type(self.container_id) is not str
            or not DIGEST.fullmatch(self.container_id)
        ):
            raise ValueError("容器重启登记需要已确认的容器和完整容器标识。")
        super().__post_init__()
        object.__setattr__(
            self,
            "target_scope",
            hashlib.sha256(canonical([self.target_scope, self.container_id])).hexdigest(),
        )


def load_container_restart_targets(path, hosts, other_writers):
    if path is None:
        return {}
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("path")
        raw, seal = _read_file(path, 16384, private=True)
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "targets"}
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["targets"]) is not dict
            or len(value["targets"]) != 1
        ):
            raise ValueError("inventory")
        host_id, record = next(iter(value["targets"].items()))
        if (
            host_id not in hosts
            or type(record) is not dict
            or set(record) != {"key_file", "policy_digest", "container_id"}
        ):
            raise ValueError("target")
        record = cast(dict[str, object], record)
        key_file, policy, container = (
            record["key_file"],
            record["policy_digest"],
            record["container_id"],
        )
        if (
            type(key_file) is not str
            or not 0 < len(key_file) <= 1024
            or type(policy) is not str
            or type(container) is not str
        ):
            raise ValueError("credential_reference")
        host = hosts[host_id]
        address = _host_address(host)
        if any(_host_address(item.host) == address for item in other_writers):
            raise ValueError("overlapping_writer")
        aliases = [
            item
            for item in hosts.values()
            if item.public.source == "ssh" and _host_address(item) == address
        ]
        if any(item.public.username == USERNAME for item in aliases):
            raise ValueError("overlapping_role")
        target = ContainerRestartTarget(
            host,
            Path(key_file),
            policy,
            tuple(item.key_file for item in aliases),
            container_id=container,
        )
        _, current = _read_file(path, 16384, private=True)
        if current != seal:
            raise ValueError("inventory_changed")
        return {host_id: target}
    except Exception:
        raise ValueError("容器重启登记、独立凭据或目标范围未能核实。") from None


def invoke(target, operation, *, policy_digest=None, **fields):
    return _invoke_fixed(
        target,
        operation,
        policy_digest,
        fields,
        command=COMMAND,
        allowed_fields=FIELDS,
        username=USERNAME,
    )
