"""Private fixture SSH evidence binding and fail-closed parsing."""

import importlib.util
import re
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "deploy/defense/ssh_fixture_evidence.py"
SPEC = importlib.util.spec_from_file_location("ssh_fixture_evidence", PATH)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)

LOG = Path("/run/opsark-ssh-defense/sshd.log")
PREFIX = b"Server listening on 127.0.0.1 port 22422.\n"
SOURCE = "127.0.0.2"


def event(port, *, source=SOURCE, outcome="Failed", user="opsark-ssh-lab"):
    return (
        f"{outcome} publickey for {user} from {source} port {port} "
        "ssh2: ED25519 SHA256:synthetic-key-fingerprint\n"
    ).encode("ascii")


@pytest.fixture
def marked(monkeypatch):
    log = [23, 401, PREFIX + event(4000)]
    monkeypatch.setattr(evidence, "_read_log", lambda path: tuple(log))
    return log, evidence.bookmark(LOG)


def test_only_new_distinct_publickey_failures_for_the_registered_peer_count(marked):
    log, mark = marked
    log[2] += b"".join(event(port) for port in range(4001, 4005))
    log[2] += event(4001) + event(5000, source="127.0.0.4") + event(5001, user="someone-else")
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, SOURCE)
    log[2] += event(4005)
    digest = evidence.inspect(LOG, mark, SOURCE)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    log[2] += (
        b"Accepted key ED25519 SHA256:synthetic-key-fingerprint found at synthetic:1\n"
        + event(6000, source="127.0.0.3", outcome="Accepted")
        + event(4006)
    )
    assert evidence.inspect(LOG, mark, SOURCE) == digest


@pytest.mark.parametrize("peer", [SOURCE, "::ffff:127.0.0.2"])
def test_any_login_from_the_candidate_peer_refuses_evidence(marked, peer):
    log, mark = marked
    log[2] += b"".join(event(port) for port in range(4001, 4006))
    log[2] += event(6000, source=peer, outcome="Accepted", user="valid-management-user")
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, SOURCE)


@pytest.mark.parametrize("peer", ["198.18.241.3", "198.18.241.5"])
def test_private_candidates_have_evidence_and_management_does_not(marked, peer):
    log, mark = marked
    management = "198.18.241.4"
    log[2] += b"".join(event(port, source=peer) for port in range(5000, 5005))
    log[2] += b"".join(event(port, source=management) for port in range(6000, 6005))
    log[2] += event(7000, source=management, outcome="Accepted")
    assert re.fullmatch(r"[0-9a-f]{64}", evidence.inspect(LOG, mark, peer))
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, management)
    log[2] += event(8000, source="::ffff:" + peer, outcome="Accepted")
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, peer)


def test_native_crlf_is_accepted_without_allowing_embedded_controls(marked):
    log, mark = marked
    log[2] += b"".join(event(port).replace(b"\n", b"\r\n") for port in range(4001, 4006))
    assert re.fullmatch(r"[0-9a-f]{64}", evidence.inspect(LOG, mark, SOURCE))
    log[2] += b"embedded\rcontrol\r\n"
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, SOURCE)


@pytest.mark.parametrize(
    "bad_append",
    [
        b"tail has no newline",
        b"Accepted malformed native message\n",
        event(65536),
        event(4050, source="127.0.00.2"),
        b"A" * 2049 + b"\n",
        b"A\n" * 257,
    ],
)
def test_malformed_or_over_budget_appends_fail_closed(marked, bad_append):
    log, mark = marked
    log[2] += b"".join(event(port) for port in range(4001, 4006)) + bad_append
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, SOURCE)


@pytest.mark.parametrize("mutation", ["inode", "prefix", "bookmark", "non_candidate"])
def test_bookmark_cannot_be_reused_with_changed_context(marked, mutation):
    log, mark = marked
    log[2] += b"".join(event(port) for port in range(4001, 4006))
    source = SOURCE
    if mutation == "inode":
        log[1] += 1
    elif mutation == "prefix":
        log[2] = log[2].replace(b"listening", b"LISTENING", 1)
    elif mutation == "bookmark":
        mark["offset"] = True
    else:
        source = "127.0.0.1"
    with pytest.raises(ValueError, match="^SSH fixture evidence could not be verified$"):
        evidence.inspect(LOG, mark, source)
