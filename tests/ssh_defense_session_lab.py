#!/usr/bin/env python3
"""Fresh auto-session profiles over the frozen, bounded business SSH laboratory.

No running authority or Root ledger is migrated. The loss case changes only its
fresh, unused lab-case selector before any container exists. The actual auto
grant is created once by the unchanged root-auto factory. Ledger persistence is
still restricted to CLI/controller restart in the same owned container.
"""

import argparse
import hashlib
import json
import os
import re
import signal
import sys
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssh_defense_business_lab as business  # noqa: E402 -- owned sibling under -I.

base, native = business.base, business.native
SELF = "/fixture-code/tests/ssh_defense_session_lab.py"
PROFILE_FILE = "session-profile.json"
PROFILES = {"auto-ack": "direct_ack", "auto-apply-loss": "exact_apply_socket_loss"}
REQUESTS_SHA256 = "db6048f38c0c750955dc8240264bd348a592e61b960f4c3ded35bfbc3c14e5c0"
TARGET_SHA256 = "533f34604bacfcec47fe49131ad935ff430a4413c1142fd38eaf4937683bcf71"
CONTROLLER_SHA256 = "6a50a61db797883cdf89bb25ee1688bc86ed465b64ee509b5f3bb126cd7b96d0"
BUSINESS_SHA256 = "f28d9c36ef56b0c89f248600afe4392b3c5710e81b4c836d6802cc5ccdb1c9a3"
FROZEN_SOURCE_SHA256 = {
    **{"deploy/defense/" + name: sha for name, sha in business.CORE_SHA256.items()},
    **{"deploy/readonly/" + name: sha for name, sha in business.READONLY_SHA256.items()},
    "tests/ssh_defense_requests_lab.py": REQUESTS_SHA256,
    "tests/ssh_defense_private_target.py": TARGET_SHA256,
    "tests/ssh_defense_lab.py": "371eeca7e75d83924d566f5aec8920eb6478482bd4053d843500a1a101a579c6",
    "tests/ssh_defense_controller_lab.py": CONTROLLER_SHA256,
    "tests/ssh_defense_business_lab.py": BUSINESS_SHA256,
}


def profile_metadata(profile):
    native.require(type(profile) is str and profile in PROFILES, "Unknown fixed session profile")
    value = {
        "schema": "opsark-session-fixture-profile/v1",
        "session_profile": profile,
        "grant_mode": "auto",
        "wire_revision": 2,
        "max_uses": 1,
        "ack_behavior": PROFILES[profile],
        "fixture_case": "root-auto" if profile == "auto-ack" else native.SOCKET_CASE,
    }
    return value | {"session_profile_sha256": native.digest(value)}


def validate_profile(value):
    native.require(type(value) is dict, "A frozen session profile is required")
    expected = profile_metadata(value.get("session_profile"))
    native.require(
        set(value) == set(expected)
        and all(
            type(value[key]) is type(want) and value[key] == want for key, want in expected.items()
        ),
        "The frozen session profile changed",
    )
    return value


def read_profile(directory):
    return validate_profile(base.read_json(directory / PROFILE_FILE))


def validate_authority(authority, expected):
    """Read only sealed synthetic authority; never inspect a Root request ledger."""
    observed = read_profile(authority)
    native.require(observed == expected, "Session authority profile changed")
    deployment = base.read_json(authority / "deployment.json")
    grants = deployment.get("defense_grants")
    native.require(type(grants) is list and len(grants) == 1, "A single fresh grant is required")
    grant = grants[0]
    native.require(
        type(grant) is dict
        and grant.get("mode") == "auto"
        and type(grant.get("mode_revision")) is int
        and grant["mode_revision"] == 2
        and type(grant.get("max_uses")) is int
        and grant["max_uses"] == 1
        and grant.get("source_aliases") == ["fixture-a"]
        and base.read_json(authority / "lab-case.json") == {"case": expected["fixture_case"]},
        "Session grant or fixed wrapper selection changed",
    )
    return deployment


def verify_source_closure(root):
    for relative, expected in FROZEN_SOURCE_SHA256.items():
        raw = native.owned_read(root / relative, 262144)
        native.require(
            b"\r\n" not in raw and hashlib.sha256(raw).hexdigest() == expected,
            "Frozen session laboratory source changed",
        )
    own = native.owned_read(root / "tests/ssh_defense_session_lab.py", 262144)
    native.require(b"\r\n" not in own, "Session source must be canonical LF")
    return FROZEN_SOURCE_SHA256 | {
        "tests/ssh_defense_session_lab.py": hashlib.sha256(own).hexdigest()
    }


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_session(workspace, policy_path, expected):
    validate_profile(expected)
    native.require(not any(workspace.iterdir()), "Session workspace must be fresh and empty")
    # A real auto authority is issued exactly once. No existing ledger is read,
    # rewritten, reinitialized, or given another use.
    staged = native.stage(workspace, "root-auto")
    code, _keys, _management, authority, _ready, state, deployment, _grants = staged
    native.require(not any(state.iterdir()), "Session request storage must remain unused")
    native.require(
        base.read_json(authority / "lab-case.json") == {"case": "root-auto"},
        "Fresh automatic factory selector changed",
    )
    if expected["session_profile"] == "auto-apply-loss":
        pending = authority / "session-case.pending"
        base.write_new(pending, {"case": native.SOCKET_CASE})
        os.replace(pending, authority / "lab-case.json")
        sync_directory(authority)
    base.write_new(authority / PROFILE_FILE, expected)
    native.require(
        validate_authority(authority, expected) == deployment,
        "Automatic authority changed before initialization",
    )
    calls = []

    def already_staged(selected_workspace, case):
        native.require(
            selected_workspace == workspace and case == native.SOCKET_CASE and not calls,
            "Business setup may consume only this fresh automatic authority once",
        )
        calls.append(True)
        return staged

    # Keep the unchanged collector/key/policy bootstrap, replacing only its
    # hard-coded factory call with the already-created fresh auto authority.
    with patch.object(native, "stage", already_staged):
        result = business.stage_business(workspace, policy_path)
    native.require(calls == [True] and result is staged, "Fresh stage was not consumed once")
    business.copy_source(Path(__file__).resolve(), code / "tests/ssh_defense_session_lab.py")
    business.copy_source(
        Path(business.__file__).resolve(), code / "tests/ssh_defense_business_lab.py"
    )
    verify_source_closure(code)
    validate_authority(authority, expected)
    return staged


def decorate(value, expected):
    validate_profile(expected)
    return value | {
        **expected,
        # This labels fixture transport behavior, never an action-success claim.
        "fault_scope": "none_direct_ack"
        if expected["session_profile"] == "auto-ack"
        else base.FAULT_SCOPE,
    }


class ProfileProof:
    def __init__(self, output, expected):
        self.output, self.expected = output, expected
        self.written = False

    def write(self, raw):
        native.require(not self.written, "Session proof is single-publication")
        value = json.loads(raw, object_pairs_hook=native.strict_pairs)
        native.require(type(value) is dict, "A structured session proof is required")
        # Profile schema is separate from the existing proof schema.
        document = decorate(value, self.expected)
        document["schema"] = "opsark-session-controller-fixture-proof/v1"
        document["source_sha256"] = verify_source_closure(Path(__file__).resolve().parents[1])
        self.written = True
        return self.output.write(native.canonical(document) + b"\n")

    def flush(self):
        return self.output.flush()

    def fileno(self):
        return self.output.fileno()


@contextmanager
def bound_entrypoint():
    with ExitStack() as stack:
        for module in (business, base, native):
            stack.enter_context(patch.object(module, "SELF", SELF))
        yield


def serve(root, image, proof, collector_policy, profile):
    native.require_root(root)
    expected = profile_metadata(profile)
    native.require(
        not any(
            (root / name).exists() or (root / name).is_symlink()
            for name in (
                PROFILE_FILE,
                "controller-ready.json",
                "supervisor.json",
                "controller-commands",
                "controller-results",
                "controller-claims",
            )
        ),
        "A session profile can only be selected for a fresh laboratory",
    )
    verify_source_closure(Path(__file__).resolve().parents[1])
    base.write_new(root / PROFILE_FILE, expected)
    original_stage, original_ready, original_proof = (
        business.stage_business,
        business.ready_value,
        native.proof_file,
    )

    def stage(workspace, policy_path):
        # The adapter itself calls the frozen business stage, not itself.
        with patch.object(business, "stage_business", original_stage):
            return stage_session(workspace, policy_path, expected)

    def ready(*args):
        workspace, deployment = args[1], args[6]
        native.require(read_profile(root) == expected, "Original session profile changed")
        native.require(
            validate_authority(workspace / "authority", expected) == deployment,
            "Ready authority changed",
        )
        value = decorate(original_ready(*args), expected)
        value["schema"] = "opsark-controller-fixture-ready/v1"
        value["source_sha256"] = verify_source_closure(workspace / "code")
        return value

    @contextmanager
    def proof_file(selected_root, selected_path):
        native.require(selected_root == root and selected_path == proof, "Proof scope changed")
        with original_proof(selected_root, selected_path) as output:
            yield ProfileProof(output, expected)

    with (
        bound_entrypoint(),
        patch.object(business, "stage_business", stage),
        patch.object(business, "ready_value", ready),
        patch.object(native, "proof_file", proof_file),
    ):
        return business.serve(root, image, proof, collector_policy)


def existing_profile(root):
    expected = read_profile(root)
    ready_path = root / "controller-ready.json"
    if ready_path.exists():
        ready = base.read_json(ready_path)
        native.require(
            all(
                type(ready.get(key)) is type(value) and ready.get(key) == value
                for key, value in expected.items()
                if key != "schema"
            ),
            "The original ready profile changed",
        )
        workspace = Path(ready["workspace"])
        native.require(workspace.parent == root, "The session workspace escaped its original root")
        # A stopped lab removes its private workspace; cached original mailbox
        # results remain readable without recreating any authority or container.
        if workspace.exists():
            validate_authority(workspace / "authority", expected)
            source_root = workspace / "code"
        else:
            native.require(
                not business.supervisor_alive(base.read_json(root / "supervisor.json")),
                "A live session lost its original authority",
            )
            source_root = Path(__file__).resolve().parents[1]
        native.require(
            ready.get("source_sha256") == verify_source_closure(source_root),
            "The original ready source closure changed",
        )
    return expected


def internal_dispatch(name, image):
    native.internal_modules()  # Same namespace/capability gate before authority reads.
    expected = read_profile(Path(native.AUTHORITY))
    validate_authority(Path(native.AUTHORITY), expected)
    if name in {"control_wrapper", "ss_close", "fault_proof"}:
        native.require(
            expected["session_profile"] == "auto-apply-loss",
            "The direct-ACK profile has no fault entrypoint",
        )
    dispatch = {
        "target": lambda: business.business_internal_target(image),
        "control_wrapper": base.controller_control_wrapper,
        "ss_close": native.internal_ss_close,
        "snapshot": native.internal_snapshot,
        "fault_proof": native.internal_fault_proof,
        "projection": base.internal_projection,
        "stimulus_gate": lambda: base.internal_projection(stimulus=True),
        "collector_traversal": business.internal_collector_traversal,
    }
    return dispatch[name]()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", choices=("describe", "serve", "status", *sorted(business.OPERATIONS))
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--collector-policy", type=Path)
    parser.add_argument("--request-id")
    parser.add_argument("--session-profile", choices=tuple(PROFILES))
    parser.add_argument("--confirm-isolated", action="store_true")
    names = (
        "target",
        "control_wrapper",
        "ss_close",
        "snapshot",
        "fault_proof",
        "projection",
        "stimulus_gate",
        "collector_traversal",
    )
    group = parser.add_mutually_exclusive_group()
    for name in names:
        group.add_argument(
            "--internal-" + name.replace("_", "-"), action="store_true", help=argparse.SUPPRESS
        )
    args = parser.parse_args(argv)
    try:
        if args.action == "describe":
            native.require(
                not any(
                    (
                        args.root,
                        args.image,
                        args.proof,
                        args.collector_policy,
                        args.request_id,
                        args.session_profile,
                    )
                ),
                "Description accepts no deployment operands",
            )
            print(
                native.canonical(
                    {
                        "profiles": [profile_metadata(p) for p in PROFILES],
                        "checks": business.business_checks(),
                        "policy": business.expected_policy(),
                    }
                ).decode("ascii")
            )
            return 0
        native.require(
            args.confirm_isolated
            and args.image is not None
            and re.fullmatch("sha256:[0-9a-f]{64}", args.image),
            "Explicit isolated mode and pinned image are required",
        )
        with bound_entrypoint():
            for name in names:
                if getattr(args, "internal_" + name):
                    native.require(
                        args.action is None and args.session_profile is None,
                        "Internal operations derive their frozen profile",
                    )
                    return internal_dispatch(name, args.image)
            native.require(args.root is not None, "A fixed private root is required")
            if args.action == "serve":
                native.require(
                    args.session_profile is not None
                    and args.proof is not None
                    and args.collector_policy is not None,
                    "A fresh profile, proof and collector policy are required",
                )
                native.require(
                    args.collector_policy.parent == args.root
                    and args.collector_policy.resolve() == args.collector_policy,
                    "Collector policy must be a direct trusted stage child",
                )
                signal.signal(signal.SIGTERM, native.interrupted)
                signal.signal(signal.SIGINT, native.interrupted)
                return serve(
                    args.root, args.image, args.proof, args.collector_policy, args.session_profile
                )
            native.require(
                args.session_profile is None,
                "Existing operations cannot replace the frozen session profile",
            )
            native.require_root(args.root)
            existing_profile(args.root)
            value = (
                business.status(args.root)
                if args.action == "status"
                else business.command(args.root, args.action, args.request_id)
            )
            print(native.canonical(value).decode("ascii"))
            return 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
        record = business._diagnostic_record
        if record is not None and record["surface"] == "target":
            with suppress(OSError, RuntimeError, ValueError, TypeError, KeyError):
                business.diagnostic_failed(error)
        print("The isolated session fixture could not be confirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
