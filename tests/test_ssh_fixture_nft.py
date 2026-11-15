"""The isolated SSH firewall verifies the whole owned policy and active action."""

import importlib.util
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "fixture_nft", Path(__file__).resolve().parents[1] / "deploy" / "defense" / "ssh_fixture_nft.py"
)
assert SPEC is not None and SPEC.loader is not None
nft = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nft)

FIRST = "a" * 32
NEXT = "b" * 32
SOURCE = "127.0.0.2"
OTHER = "127.0.0.4"
MANAGEMENT = "127.0.0.3"
EMPTY = """table ip opsark_ssh_lab {
    set blocked {
        type ipv4_addr
        size 1
        timeout 1m
    }

    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" ct state new ip daddr 127.0.0.1 tcp dport 22422 ip saddr { 127.0.0.2, 127.0.0.4 } ip saddr @blocked drop
    }
}
"""  # noqa: E501 -- copied command output contains a single rule line.
PRIVATE = (
    EMPTY.replace('iifname "lo"', 'iifname "eth0"')
    .replace("ip daddr 127.0.0.1", "ip daddr 198.18.241.2")
    .replace("127.0.0.2, 127.0.0.4", "198.18.241.3, 198.18.241.5")
)
LIST = ("--numeric-priority", "list", "table", "ip", "opsark_ssh_lab")


def with_element(source=SOURCE, ttl="59s996ms", action=FIRST, *, table=EMPTY):
    return table.replace(
        "        timeout 1m\n",
        (
            f"        timeout 1m\n        elements = {{ {source} expires {ttl} "
            f'comment "opsark-{action}" }}\n'
        ),
    )


@pytest.mark.parametrize(
    ("expiry", "expected"),
    [
        ("1m", 60000),
        ("59s996ms", 59996),
        ("45s", 45000),
        ("831ms", 831),
        ("0ms", 0),
    ],
)
def test_precise_kernel_ttl_and_identity(expiry, expected):
    assert nft._owned_state(EMPTY) is None
    assert nft._owned_state(with_element(ttl=expiry)) == (
        (SOURCE, expected, FIRST) if expected else None
    )


@pytest.mark.parametrize(
    "output",
    [
        with_element(source=MANAGEMENT),
        with_element(ttl="60s1ms"),
        with_element(action="a" * 31),
        with_element().replace(' comment "opsark-' + FIRST + '"', ""),
        with_element().replace("size 1", "size 2"),
        with_element().replace("timeout 1m", "timeout 2m"),
        with_element().replace('iifname "lo"', 'iifname "eth0"'),
        with_element().replace("ct state new", "ct state established"),
        with_element().replace("tcp dport 22422", "tcp dport 22"),
        with_element().replace("ip daddr 127.0.0.1", "ip daddr 127.0.0.5"),
        with_element().replace("127.0.0.2, 127.0.0.4", "127.0.0.2, 127.0.0.3"),
        with_element().replace("@blocked drop", "@blocked accept"),
        with_element().replace("policy accept;", "policy drop;"),
        with_element() + "table ip extra {}",
    ],
)
def test_policy_drift_and_untrusted_element_fail_closed(output):
    with pytest.raises(nft.NftError):
        nft._owned_state(output)


def test_initialize_exclusively_creates_fixed_empty_policy(monkeypatch):
    calls = []
    states = iter(("table ip other\n", "", EMPTY, "table ip opsark_ssh_lab\n", EMPTY))

    def run(*args, script=None):
        calls.append((args, script))
        return next(states)

    monkeypatch.setattr(nft, "_run", run)
    nft.initialize()
    nft.initialize()
    assert [args for args, _ in calls] == [
        ("list", "tables", "ip"),
        ("-f", "-"),
        LIST,
        ("list", "tables", "ip"),
        LIST,
    ]
    assert calls[1][1].startswith(b"create table ip opsark_ssh_lab\n")
    assert b"size 1; flags timeout; timeout 60s" in calls[1][1]
    assert b"flush" not in calls[1][1]
    assert all(script is None for index, (_, script) in enumerate(calls) if index != 1)


def test_writes_are_scoped_and_replay_cannot_refresh_or_revoke_newer_action(monkeypatch):
    state = EMPTY
    writes = []

    def run(*args, script=None):
        nonlocal state
        if script is None:
            assert args == LIST
            return state
        assert args == ("-f", "-")
        writes.append(script.decode())
        state = with_element() if script.startswith(b"create element") else EMPTY
        return ""

    monkeypatch.setattr(nft, "_run", run)
    nft.add(SOURCE, FIRST)
    nft.add(SOURCE, FIRST)
    for source, action in ((SOURCE, NEXT), (OTHER, FIRST)):
        with pytest.raises(nft.NftError):
            nft.add(source, action)
        with pytest.raises(nft.NftError):
            nft.remove(source, action)
    nft.remove(SOURCE, FIRST)
    nft.remove(SOURCE, FIRST)
    state = with_element(action=NEXT)
    with pytest.raises(nft.NftError):
        nft.remove(SOURCE, FIRST)
    assert writes == [
        f"create element ip opsark_ssh_lab blocked {{ {SOURCE} timeout 60s "
        f'comment "opsark-{FIRST}" }}\n',
        f"delete element ip opsark_ssh_lab blocked {{ {SOURCE} }}\n",
    ]


def test_validation_before_nft_and_confirmation_after_add(monkeypatch):
    commands = []

    def run(*args, script=None):
        commands.append((args, script))
        return EMPTY

    monkeypatch.setattr(nft, "_run", run)
    for source, action in (
        (MANAGEMENT, FIRST),
        ("127.0.0.2 ; flush ruleset", FIRST),
        (SOURCE, '"'),
    ):
        for mutate in (nft.add, nft.remove):
            with pytest.raises(nft.NftError):
                mutate(source, action)
    assert not commands
    with pytest.raises(nft.NftError, match="was not verified"):
        nft.add(SOURCE, FIRST)
    assert [args for args, _ in commands] == [LIST, ("-f", "-"), LIST]


def test_private_profile_is_fixed_and_does_not_adopt_loopback_or_management(monkeypatch):
    state = ""
    writes = []

    def run(*args, script=None):
        nonlocal state
        if args == ("list", "tables", "ip"):
            return "table ip opsark_ssh_lab\n" if state else ""
        if args == LIST:
            return state
        assert args == ("-f", "-") and script is not None
        writes.append(script)
        if script.startswith(b"create element"):
            peer = "198.18.241.3" if b"198.18.241.3" in script else "198.18.241.5"
            state = with_element(peer, table=PRIVATE)
        else:
            state = PRIVATE
        return ""

    monkeypatch.setattr(nft, "_run", run)
    nft.initialize(profile="private")
    nft.initialize(profile="private")
    assert nft.observe(profile="private") is None
    assert b'iifname "eth0" ct state new ip daddr 198.18.241.2 tcp dport 22422 ' in writes[0]
    assert b"ip saddr { 198.18.241.3, 198.18.241.5 } ip saddr @blocked drop" in writes[0]
    assert b"198.18.241.4" not in writes[0]
    with pytest.raises(nft.NftError, match="policy differs"):
        nft.initialize()
    state = with_element("198.18.241.4", table=PRIVATE)
    with pytest.raises(nft.NftError, match="policy differs"):
        nft.observe(profile="private")
    state = PRIVATE
    for denied in (SOURCE, "198.18.241.2", "198.18.241.4"):
        for mutate in (nft.add, nft.remove):
            with pytest.raises(nft.NftError, match="action identity"):
                mutate(denied, FIRST, profile="private")
    assert len(writes) == 1

    for peer in ("198.18.241.3", "198.18.241.5"):
        nft.add(peer, FIRST, profile="private")
        nft.add(peer, FIRST, profile="private")
        assert nft.observe(profile="private") == (peer, 59996, FIRST)
        with pytest.raises(nft.NftError, match="Another .* action"):
            nft.remove(peer, NEXT, profile="private")
        nft.remove(peer, FIRST, profile="private")
        assert nft.observe(profile="private") is None
    assert len(writes) == 5


def test_invalid_profile_is_refused_before_any_tool_call(monkeypatch):
    monkeypatch.setattr(nft, "_run", lambda *args, **kwargs: pytest.fail("tool called"))
    for name in ("Private", "private\n", "public", {}, None):
        for action, args in (
            (nft.initialize, ()),
            (nft.observe, ()),
            (nft.add, (SOURCE, FIRST)),
            (nft.remove, (SOURCE, FIRST)),
        ):
            with pytest.raises(nft.NftError, match="Unknown .* profile"):
                action(*args, profile=name)


@pytest.mark.skipif(sys.platform != "linux", reason="The real selector requires Linux pipes")
def test_command_budget_caps_output_and_refuses_a_hanging_tool(monkeypatch):
    monkeypatch.setattr(nft, "_NFT", sys.executable)
    with pytest.raises(nft.NftError, match="output limit"):
        nft._run("-c", "print('x' * 9000)")
    monkeypatch.setattr(nft, "_TIMEOUT", 0.1)
    with pytest.raises(nft.NftError, match="timed out"):
        nft._run("-c", "import time; time.sleep(5)")
