#!/usr/bin/env python3
"""Verify a staged certificate renewal against two real isolated Nginx runtimes."""

import argparse
import json
import re
import secrets
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from deploy.nginx import config_snapshot, fixture_action, fixture_context, fixture_renewal
from deploy.nginx.fixture_runtime import FixtureRuntime, RuntimeRefused
from tests.nginx_fixture_action_acceptance import (
    cli,
    native_tls,
    require_root,
    run_fixture,
    worker,
    write_runtime,
)
from tests.nginx_fixture_pki import generate_chain_tls, generate_renewal_tls

_RECEIPT = "renewal-pending.json"


def _write_workspace(workspace: Path) -> Path:
    workspace.mkdir(mode=0o700)
    workspace.chmod(0o700)
    marker = workspace / fixture_action.WORKSPACE_MARKER
    marker.write_bytes(fixture_action.WORKSPACE_MARKER_CONTENT)
    marker.chmod(0o600)
    config = workspace / "etc/nginx/conf.d"
    config.mkdir(mode=0o755, parents=True)
    config.chmod(0o755)
    machine = workspace / "etc/machine-id"
    machine.write_text(secrets.token_hex(16) + "\n", encoding="ascii")
    machine.chmod(0o600)
    (workspace / "actions").mkdir(mode=0o700)
    write_runtime(workspace, rich=True, chain=True)
    target = config / fixture_action.TARGET_NAME
    target.write_bytes(fixture_action.ORIGINAL)
    target.chmod(0o644)
    return target


def _seal(workspace: Path) -> fixture_context.RuntimeContext:
    return fixture_context.seal_context(fixture_action.fixture_policy(workspace), tls_chain=True)


def _file_proof(path: Path) -> tuple[bytes, tuple[int, ...]]:
    info = path.stat()
    return path.read_bytes(), (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_refusal(current: FixtureRuntime, candidate: FixtureRuntime, expected: str) -> None:
    try:
        fixture_renewal.prepare(current, candidate, expected_context_sha256=expected)
    except (config_snapshot.SnapshotError, RuntimeRefused):
        return
    raise AssertionError("The isolated renewal preparation unexpectedly accepted invalid evidence")


def _prove_sni(runtime: FixtureRuntime) -> None:
    # The native handshake independently checks SNI and trust. The runtime probe
    # additionally pins each live leaf and intermediate to that workspace's seal.
    assert all(native_tls(runtime, hostname) for hostname in fixture_context.CHAIN_HOSTS.values())
    assert runtime._probe(b"original")


def _verify_handoff(
    result: dict,
    original: fixture_context.RuntimeContext,
    renewed: fixture_context.RuntimeContext,
) -> None:
    old, new = original.tls_chain, renewed.tls_chain
    assert old is not None and new is not None
    hosts = fixture_context.CHAIN_HOSTS
    target = hosts["target"]
    assert old.root_sha256 == new.root_sha256
    assert old.leaf_sha256[target] != new.leaf_sha256[target]
    for role in ("control", "default"):
        host = hosts[role]
        assert old.leaf_sha256[host] == new.leaf_sha256[host]
        assert old.chain_sha256[host] == new.chain_sha256[host]

    assert set(result) == {
        "schema_version",
        "status",
        "handoff_id",
        "old_leaf_sha256",
        "new_leaf_sha256",
        "current_context_sha256",
        "candidate_context_sha256",
        "old_not_after",
        "new_not_after",
        "old_chain_not_after",
        "new_chain_not_after",
    }
    assert result["schema_version"] == 1 and result["status"] == "pending_approval"
    assert re.fullmatch(r"[0-9a-f]{64}", result["handoff_id"])
    assert result["old_leaf_sha256"] == old.leaf_sha256[target]
    assert result["new_leaf_sha256"] == new.leaf_sha256[target]
    assert result["current_context_sha256"] == original.fingerprint
    assert result["candidate_context_sha256"] == renewed.fingerprint
    assert original.fingerprint != renewed.fingerprint
    old_leaf = datetime.fromisoformat(result["old_not_after"])
    new_leaf = datetime.fromisoformat(result["new_not_after"])
    old_chain = datetime.fromisoformat(result["old_chain_not_after"])
    new_chain = datetime.fromisoformat(result["new_chain_not_after"])
    assert old_chain <= old_leaf < new_leaf and old_chain < new_chain <= new_leaf


def _exercise_pair(root: Path, image: str, docker_config: str, *, unrelated: bool) -> None:
    workspace = root / ("opsark-nginx-fixture-" + secrets.token_hex(8))
    renewed_workspace = fixture_renewal.candidate_workspace(workspace)
    assert renewed_workspace.parent == workspace.parent and renewed_workspace != workspace
    targets = (_write_workspace(workspace), _write_workspace(renewed_workspace))
    assert cli("renewal-candidate", "--workspace", str(workspace)) == (
        0,
        {"workspace_name": renewed_workspace.name},
    )
    if unrelated:
        generate_chain_tls(workspace / "tls")
        # The candidate is a valid longer-lived renewal, but from a different CA.
        with TemporaryDirectory(prefix="unrelated-pki-", dir=root) as other:
            generate_renewal_tls(Path(other) / "tls", renewed_workspace / "tls")
    else:
        generate_renewal_tls(workspace / "tls", renewed_workspace / "tls")
    original, renewed = _seal(workspace), _seal(renewed_workspace)
    receipt = workspace / _RECEIPT
    candidate_receipt = renewed_workspace / _RECEIPT
    expected = original.fingerprint
    inspect_args = ("inspect-renewal", "--workspace", str(workspace))

    with (
        run_fixture(workspace, image, docker_config) as current,
        run_fixture(renewed_workspace, image, docker_config) as candidate,
    ):
        _prove_sni(current)
        _prove_sni(candidate)
        processes = (current.fingerprint(), candidate.fingerprint())
        workers = (worker(current), worker(candidate))
        sites = tuple(_file_proof(target) for target in targets)
        assert fixture_renewal.inspect(workspace) is None
        if unrelated:
            assert original.tls_chain is not None and renewed.tls_chain is not None
            assert original.tls_chain.root_sha256 != renewed.tls_chain.root_sha256
            _require_refusal(current, candidate, expected)
            assert fixture_renewal.inspect(workspace) is None and not receipt.exists()
        else:
            _require_refusal(current, candidate, renewed.fingerprint)
            assert fixture_renewal.inspect(workspace) is None and not receipt.exists()

            code, result = cli(
                "prepare-renewal",
                "--workspace",
                str(workspace),
                "--container",
                current.container,
                "--candidate-container",
                candidate.container,
                "--image",
                image,
                "--expected-context-sha256",
                expected,
            )
            assert code == 0
            _verify_handoff(result, original, renewed)
            saved = _file_proof(receipt)
            assert receipt.stat().st_mode & 0o777 == 0o600
            assert cli(*inspect_args) == (0, result)
            assert (
                fixture_renewal.prepare(current, candidate, expected_context_sha256=expected)
                == result
            )
            _require_refusal(current, candidate, renewed.fingerprint)

            # Remove only the seal of the candidate fixture while its real TLS remains live.
            seal = renewed_workspace / "runtime-context"
            saved_seal = seal.with_name("acceptance-saved-context")
            seal.rename(saved_seal)
            try:
                assert native_tls(candidate, fixture_context.CHAIN_HOSTS["target"])
                _require_refusal(current, candidate, expected)
                assert cli(*inspect_args) == (0, result)
            finally:
                saved_seal.rename(seal)

            assert fixture_renewal.inspect(workspace) == result
            assert _file_proof(receipt) == saved

        assert not candidate_receipt.exists()
        assert tuple(_file_proof(target) for target in targets) == sites
        assert (current.fingerprint(), candidate.fingerprint()) == processes
        assert (worker(current), worker(candidate)) == workers
        _prove_sni(current)
        _prove_sni(candidate)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    require_root(args.root)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise RuntimeError("A pinned fixture image is required")
    with (
        TemporaryDirectory(prefix="renewal-acceptance-", dir=args.root) as root,
        TemporaryDirectory(prefix="opsark-renewal-docker-", dir="/tmp") as docker_config,
    ):
        _exercise_pair(Path(root), args.image, docker_config, unrelated=False)
        _exercise_pair(Path(root), args.image, docker_config, unrelated=True)
    print(
        json.dumps(
            {
                "pending_handoff_verified": True,
                "retry_preserved_receipt": True,
                "no_fixture_reload_or_site_write": True,
                "old_and_new_sni_chains_independently_verified": True,
                "wrong_current_seal_and_unsealed_candidate_rejected": True,
                "unrelated_trust_root_rejected": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
