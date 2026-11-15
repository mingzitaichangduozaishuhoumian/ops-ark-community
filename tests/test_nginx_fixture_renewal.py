"""Check the trust, lifetime and workspace policy of target-only fixture renewal."""

import importlib
import os
import re
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

import pytest

TARGET = "target.opsark.invalid"
CONTROL = "control.opsark.invalid"
DEFAULT = "unknown.opsark.invalid"
HOSTS = (TARGET, CONTROL, DEFAULT)
NOW = datetime(2026, 11, 5, tzinfo=UTC)


@pytest.fixture
def renewal(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.import_module("deploy.nginx.fixture_renewal")


@pytest.fixture
def snapshot_error(renewal):
    return importlib.import_module("deploy.nginx.config_snapshot").SnapshotError


@pytest.fixture
def materials(renewal):
    context = importlib.import_module("deploy.nginx.fixture_context")
    original = context.TLSChainMaterial(
        directory={"dev": 1, "ino": 10},
        files={"target-key.pem": {"dev": 1, "ino": 11}},
        leaf_sha256={name: str(index) * 64 for index, name in enumerate(HOSTS, 1)},
        intermediate_sha256=dict.fromkeys(HOSTS, "4" * 64),
        chain_sha256={name: str(index) * 64 for index, name in enumerate(HOSTS, 5)},
        root_sha256="8" * 64,
        root_pem_sha256="9" * 64,
    )
    candidate = replace(
        original,
        directory={"dev": 1, "ino": 20},
        files={"target-key.pem": {"dev": 1, "ino": 21}},
        leaf_sha256={**original.leaf_sha256, TARGET: "a" * 64},
        chain_sha256={**original.chain_sha256, TARGET: "b" * 64},
    )
    return original, candidate


def test_candidate_workspace_is_a_deterministic_distinct_sibling(renewal):
    # Pure POSIX paths let the lexical Linux contract run on Windows CI too.
    root = PurePosixPath("/var/lib/opsark-lab")
    first = root / ("opsark-nginx-fixture-" + "a" * 12)
    second = root / ("opsark-nginx-fixture-" + "b" * 32)
    first_candidate = renewal.candidate_workspace(first)
    second_candidate = renewal.candidate_workspace(second)
    assert first_candidate == renewal.candidate_workspace(first)
    assert first_candidate != first and second_candidate != second
    assert first_candidate != second_candidate
    for candidate in (first_candidate, second_candidate):
        assert candidate.parent == root
        assert re.fullmatch(r"opsark-nginx-fixture-[0-9a-f]{32}", candidate.name)


@pytest.mark.parametrize(
    "workspace",
    [
        "opsark-nginx-fixture-" + "a" * 12,
        "/var/lib/../opsark-nginx-fixture-" + "a" * 12,
        "/var/lib/other-fixture-" + "a" * 12,
        "/var/lib/opsark-nginx-fixture-" + "a" * 11,
        "/var/lib/opsark-nginx-fixture-" + "a" * 33,
        "/var/lib/opsark-nginx-fixture-" + "A" * 12,
        "/var/lib/opsark-nginx-fixture-" + "a" * 12 + ".old",
    ],
)
def test_candidate_workspace_refuses_noncanonical_path_or_invalid_name(
    renewal, snapshot_error, workspace
):
    with pytest.raises(snapshot_error):
        renewal.candidate_workspace(PurePosixPath(workspace))


def test_target_renewal_keeps_root_intermediate_and_sibling_material(renewal, materials):
    original, candidate = materials
    # The candidate has new directory and key inodes. Those must not be mistaken
    # for changes to the pinned trust or sibling certificate chains.
    renewal._require_same_trust(original, candidate)


@pytest.mark.parametrize(
    ("field", "hostname"),
    [
        ("root_pem_sha256", None),
        ("intermediate_sha256", TARGET),
        ("intermediate_sha256", CONTROL),
        ("intermediate_sha256", DEFAULT),
        ("chain_sha256", CONTROL),
        ("chain_sha256", DEFAULT),
    ],
)
def test_target_renewal_refuses_any_pinned_dependency_change(
    renewal, snapshot_error, materials, field, hostname
):
    original, candidate = materials
    changed = "f" * 64
    if hostname is not None:
        changed = {**getattr(candidate, field), hostname: changed}
    with pytest.raises(snapshot_error):
        renewal._require_same_trust(original, replace(candidate, **{field: changed}))


def test_reencoded_target_chain_is_not_a_leaf_renewal(renewal, snapshot_error, materials):
    original, candidate = materials
    with pytest.raises(snapshot_error):
        renewal._require_same_trust(
            original,
            replace(
                candidate,
                leaf_sha256={**candidate.leaf_sha256, TARGET: original.leaf_sha256[TARGET]},
            ),
        )


def dates(leaf: int, effective: int) -> tuple[datetime, datetime]:
    return NOW + timedelta(seconds=leaf), NOW + timedelta(seconds=effective)


def test_renewal_accepts_exactly_one_hour_remaining_after_both_expiries_improve(renewal):
    old = dates(7200, 3599)
    new = dates(10800, 3600)
    renewal._verify_dates(old, new, NOW)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        pytest.param(dates(28800, 7200), dates(28800, 10800), id="leaf-not-improved"),
        pytest.param(dates(28800, 7200), dates(21600, 10800), id="leaf-shortened"),
        pytest.param(dates(28800, 7200), dates(86400, 7200), id="chain-not-improved"),
        pytest.param(dates(28800, 7200), dates(86400, 5400), id="chain-shortened"),
        pytest.param(dates(7200, 3598), dates(10800, 3599), id="less-than-one-hour-left"),
        pytest.param(dates(7200, 0), dates(10800, 3600), id="old-chain-expiring-now"),
        pytest.param(dates(7200, -1), dates(10800, 3600), id="old-chain-expired"),
    ],
)
def test_renewal_rejects_weaker_or_insufficient_validity(renewal, snapshot_error, old, new):
    with pytest.raises(snapshot_error):
        renewal._verify_dates(old, new, NOW)


def _openssl_result(monkeypatch, renewal, *, stdout: bytes, returncode: int = 0):
    def run(command, **kwargs):
        assert command == ["/usr/bin/openssl", "x509", "-noout", "-dates", "-dateopt", "iso_8601"]
        assert kwargs["input"] == b"public certificate block"
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 2
        return subprocess.CompletedProcess(command, returncode, stdout)

    monkeypatch.setattr(renewal.subprocess, "run", run)


def test_public_dates_accepts_the_exact_validity_start(monkeypatch, renewal):
    _openssl_result(
        monkeypatch,
        renewal,
        stdout=b"notBefore=2026-11-05 00:00:00Z\nnotAfter=2026-11-05 01:00:00Z\n",
    )
    assert renewal._public_dates(b"public certificate block", NOW) == NOW + timedelta(hours=1)


@pytest.mark.parametrize(
    ("stdout", "returncode"),
    [
        pytest.param(b"unexpected openssl output\n", 0, id="invalid-output"),
        pytest.param(b"\xff\xfe", 0, id="non-ascii-output"),
        pytest.param(
            b"notBefore=2026-11-31 00:00:00Z\nnotAfter=2026-12-05 01:00:00Z\n",
            0,
            id="invalid-calendar-date",
        ),
        pytest.param(
            b"notBefore=2026-11-05 00:00:01Z\nnotAfter=2026-11-05 01:00:00Z\n",
            0,
            id="not-yet-valid",
        ),
        pytest.param(
            b"notBefore=2026-11-04 00:00:00Z\nnotAfter=2026-11-05 00:00:00Z\n",
            0,
            id="expired-at-current-time",
        ),
        pytest.param(
            b"notBefore=2026-11-05 00:00:00Z\nnotAfter=2026-11-05 01:00:00Z\n",
            1,
            id="openssl-failed",
        ),
        pytest.param(b"x" * 129, 0, id="oversized-output"),
    ],
)
def test_public_dates_refuses_unconfirmed_validity(
    monkeypatch, renewal, snapshot_error, stdout, returncode
):
    _openssl_result(monkeypatch, renewal, stdout=stdout, returncode=returncode)
    with pytest.raises(snapshot_error):
        renewal._public_dates(b"public certificate block", NOW)


def test_pending_receipt_round_trips_through_the_private_journal(renewal, snapshot_error, tmp_path):
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("requires the trusted Linux journal owner")
    binding = "a" * 64
    proof = {
        "schema_version": 1,
        "status": "pending_approval",
        "current_context_sha256": "b" * 64,
        "candidate_context_sha256": "c" * 64,
        "old_leaf_sha256": "d" * 64,
        "new_leaf_sha256": "e" * 64,
        "old_not_after": "2026-11-06 00:00:00Z",
        "new_not_after": "2026-11-07 00:00:00Z",
        "old_chain_not_after": "2026-11-06 00:00:00Z",
        "new_chain_not_after": "2026-11-07 00:00:00Z",
    }
    proof["handoff_id"] = renewal._handoff_id(proof, binding)
    record = {"proof": proof, "binding_sha256": binding}
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert renewal._read_receipt(directory) is None
        renewal.action_journal._publish(directory, renewal._RECEIPT, record, renewal._SEAL)
        assert renewal._read_receipt(directory) == record
        assert renewal._safe_proof(renewal._read_receipt(directory)) == proof
    finally:
        os.close(directory)
    with pytest.raises(snapshot_error):
        renewal._safe_proof({**record, "unexpected": "synthetic secret marker"})
