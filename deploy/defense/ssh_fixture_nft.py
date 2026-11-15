"""One temporary SSH block in an independently authorized isolated network namespace.

The executor must serialize calls under its fixture lock and be the only writer.
This module never selects a network namespace or accepts policy or tool paths.
"""

import os
import re
import selectors
import subprocess
import time
from typing import NamedTuple

_NFT = "/usr/sbin/nft"
_TABLE = "opsark_ssh_lab"
_SET = "blocked"
_ACTION = r"[0-9a-f]{32}"
_TTL_MS = 60_000
_TIMEOUT = 3
_OUTPUT_LIMIT = 8192


class NftError(RuntimeError):
    """The fixture nftables action was refused or its result could not be verified."""


class _Policy(NamedTuple):
    sources: tuple[str, str]
    init: bytes
    owned: re.Pattern[str]


def _fixed_policy(interface, target, sources: tuple[str, str]) -> _Policy:
    rule = (
        f'iifname "{interface}" ct state new ip daddr {target} tcp dport 22422 '
        f"ip saddr {{ {sources[0]}, {sources[1]} }} ip saddr @{_SET} drop"
    )
    init = (
        f"create table ip {_TABLE}\n"
        f"add set ip {_TABLE} {_SET} {{ type ipv4_addr; size 1; flags timeout; timeout 60s; }}\n"
        f"add chain ip {_TABLE} input {{ type filter hook input priority 0; policy accept; }}\n"
        f"add rule ip {_TABLE} input {rule}\n"
    ).encode("ascii")
    source_pattern = "|".join(map(re.escape, sources))
    owned = re.compile(
        rf"table ip {_TABLE} {{ set {_SET} {{ type ipv4_addr size 1"
        r"(?: flags timeout)? timeout (?:1m|60s)"
        rf"(?: elements = {{ (?P<source>{source_pattern})(?: timeout (?:1m|60s))?"
        r" expires (?P<ttl>1m|[0-9]{1,2}s(?:[0-9]{1,3}ms)?|[0-9]{1,3}ms)"
        rf' comment "opsark-(?P<action>{_ACTION})" }})? }} '
        r"chain input \{ type filter hook input priority 0; policy accept; "
        + re.escape(rule)
        + r" \} \}"
    )
    return _Policy(sources, init, owned)


_PROFILES = {
    "loopback": _fixed_policy("lo", "127.0.0.1", ("127.0.0.2", "127.0.0.4")),
    "private": _fixed_policy("eth0", "198.18.241.2", ("198.18.241.3", "198.18.241.5")),
}


def _select_profile(profile: str) -> _Policy:
    if type(profile) is not str or profile not in _PROFILES:
        raise NftError("Unknown fixture nftables profile")
    return _PROFILES[profile]


def _read_stdout(pipe, deadline):
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(pipe, selectors.EVENT_READ)
        while True:
            if not selector.select(max(0, deadline - time.monotonic())):
                raise NftError("Fixture nftables command timed out")
            chunk = os.read(pipe.fileno(), _OUTPUT_LIMIT + 1 - len(output))
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > _OUTPUT_LIMIT:
                raise NftError("Fixture nftables output limit exceeded")


def _run(*arguments, script: bytes | None = None):
    deadline = time.monotonic() + _TIMEOUT
    try:
        with subprocess.Popen(  # noqa: S603 -- fixed binary and private constant argv/templates.
            [_NFT, *arguments],
            stdin=subprocess.PIPE if script is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        ) as process:
            try:
                if script is not None and process.stdin is not None:
                    process.stdin.write(script)
                    process.stdin.close()
                output = _read_stdout(process.stdout, deadline)
                if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                    raise NftError("Fixture nftables command failed")
                return output.decode("ascii")
            finally:
                if process.poll() is None:
                    process.kill()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise NftError("Fixture nftables command could not be verified") from None


def _owned_state(output, *, profile="loopback"):
    match = _select_profile(profile).owned.fullmatch(" ".join(output.split()))
    if match is None:
        raise NftError("Owned fixture nftables policy differs")
    source = match["source"]
    if source is None:
        return None
    ttl = match["ttl"]
    if ttl == "1m":
        remaining = _TTL_MS
    else:
        parts = re.fullmatch(r"(?:([0-9]+)s)?(?:([0-9]+)ms)?", ttl)
        if parts is None:
            raise NftError("Invalid fixture nftables expiry")
        remaining = 1000 * int(parts[1] or 0) + int(parts[2] or 0)
    if not 0 <= remaining <= _TTL_MS:
        raise NftError("Invalid fixture nftables expiry")
    return (source, remaining, match["action"]) if remaining else None


def _identity(source, action_id, profile):
    policy = _select_profile(profile)
    if (
        type(source) is not str
        or source not in policy.sources
        or not isinstance(action_id, str)
        or not re.fullmatch(_ACTION, action_id)
    ):
        raise NftError("Invalid fixture nftables action identity")


def initialize(*, profile: str = "loopback") -> None:
    """Create the fixed table atomically, or validate an existing owned table."""
    policy = _select_profile(profile)
    tables = _run("list", "tables", "ip")
    if f"table ip {_TABLE}" in tables.splitlines():
        observe(profile=profile)
        return
    _run("-f", "-", script=policy.init)
    if observe(profile=profile) is not None:
        raise NftError("New fixture nftables table was not empty")


def observe(*, profile: str = "loopback") -> tuple[str, int, str] | None:
    """Return source, remaining kernel TTL in milliseconds, and exact action ID."""
    _select_profile(profile)
    return _owned_state(_run("--numeric-priority", "list", "table", "ip", _TABLE), profile=profile)


def add(source: str, action_id: str, *, profile: str = "loopback") -> None:
    """Create one kernel-timed element without refreshing an active action."""
    _identity(source, action_id, profile)
    current = observe(profile=profile)
    if current is not None:
        if (current[0], current[2]) != (source, action_id):
            raise NftError("Another fixture nftables action is active")
        return
    _run(
        "-f",
        "-",
        script=(
            f"create element ip {_TABLE} {_SET} {{ {source} timeout 60s "
            f'comment "opsark-{action_id}" }}\n'
        ).encode("ascii"),
    )
    current = observe(profile=profile)
    if current is None or (current[0], current[2]) != (source, action_id):
        raise NftError("Created fixture nftables element was not verified")


def remove(source: str, action_id: str, *, profile: str = "loopback") -> None:
    """Delete only the still-active element bound to this exact action."""
    _identity(source, action_id, profile)
    current = observe(profile=profile)
    if current is None:
        return
    if (current[0], current[2]) != (source, action_id):
        raise NftError("Another fixture nftables action is active")
    _run("-f", "-", script=f"delete element ip {_TABLE} {_SET} {{ {source} }}\n".encode("ascii"))
    if observe(profile=profile) is not None:
        raise NftError("Removed fixture nftables element was not verified")
