"""Export one registered host's exact collection policy without contacting SSH."""

import argparse
import hashlib
import json
import os
import secrets
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from opsark.business_readiness import commands_for_business  # noqa: E402 -- standalone CLI.
from opsark.collector import commands_for, commands_for_preflight, nginx_dependencies_command  # noqa: E402 -- standalone CLI.
from opsark.compose_discovery import commands_for_compose_discovery  # noqa: E402
from opsark.compose_generation import collection_command as generation_command  # noqa: E402
from opsark.compose_volume_metadata import collection_command  # noqa: E402
from opsark.config import Settings, load_hosts  # noqa: E402
from opsark.security_events import SECURITY_COMMAND  # noqa: E402
from opsark.ssh_defense_status import commands_for_defense_status  # noqa: E402
from opsark.web_security_events import SECURITY_WEB_COMMAND  # noqa: E402


def export_policy(inventory, host_id, output):
    if not inventory.is_absolute() or not output.is_absolute():
        raise ValueError("Inventory and output paths must be absolute")
    settings = Settings(
        data_dir=output.parent,
        token=secrets.token_urlsafe(32),
        inventory_path=inventory,
    )
    hosts = load_hosts(settings)
    if host_id not in hosts:
        raise ValueError("Host identifier is not registered")
    commands = {}
    for scenario in ("web_502", "disk", "container_restart", "ssh_security"):
        for command in commands_for(hosts[host_id], scenario).values():
            commands["LC_ALL=C " + command] = shlex.split(command)
    for command in commands_for_preflight(hosts[host_id]).values():
        commands["LC_ALL=C " + command] = shlex.split(command)
    if hosts[host_id].nginx_scope_digest is not None:
        command = nginx_dependencies_command(hosts[host_id])
        commands["LC_ALL=C " + command] = shlex.split(command)
    compose_project = hosts[host_id].compose_project
    if compose_project is not None:
        for command in commands_for_compose_discovery(hosts[host_id], compose_project).values():
            commands["LC_ALL=C " + command] = shlex.split(command)
    if hosts[host_id].compose_volume_scope_digest is not None:
        command = collection_command(hosts[host_id])
        commands["LC_ALL=C " + command] = shlex.split(command)
    if hosts[host_id].compose_generation_scope_digest is not None:
        command = generation_command(hosts[host_id])
        commands["LC_ALL=C " + command] = shlex.split(command)
    for command in commands_for_business(hosts[host_id]).values():
        commands["LC_ALL=C " + command] = shlex.split(command)
    for command in commands_for_defense_status(hosts[host_id]).values():
        commands["LC_ALL=C " + command] = shlex.split(command)
    commands["LC_ALL=C " + SECURITY_COMMAND] = shlex.split(SECURITY_COMMAND)
    if hosts[host_id].public.web_profile_digest:
        commands["LC_ALL=C " + SECURITY_WEB_COMMAND] = shlex.split(SECURITY_WEB_COMMAND)
    payload = (
        json.dumps({"schema_version": 1, "commands": commands}, sort_keys=True) + "\n"
    ).encode()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("Policy output cannot be a symbolic link")
    temporary = output.with_name("." + output.name + ".opsark-export-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "host_id": host_id,
        "allowed_commands": len(commands),
        "policy_sha256": hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = export_policy(arguments.inventory, arguments.host_id, arguments.output)
    except (OSError, ValueError):
        print(
            "Cannot export policy; verify the private inventory, host id and output.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
