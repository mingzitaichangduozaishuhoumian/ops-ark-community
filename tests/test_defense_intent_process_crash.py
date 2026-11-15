"""Real os._exit boundaries; all keys, ledgers and Root receipts are synthetic.

The accepted boundary is a durable fake-invoker acceptance before Controller
receipt commit. It is not evidence of real SSH delivery or live Root recovery.
"""

import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing, nullcontext
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from test_defense_api import (  # noqa: E402
    EVIDENCE,
    NOW,
    SOURCE,
    FakeRoot,
    ready,
)
from test_defense_api import (  # noqa: E402
    harness as harness,
)
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402

from opsark.automation_store import AutomationStore  # noqa: E402
from opsark.baselines import scope_for  # noqa: E402
from opsark.config import HostConfig, Settings  # noqa: E402
from opsark.control_modes import ControlPolicy  # noqa: E402
from opsark.defense_api import ApplyRequest, DefenseService  # noqa: E402
from opsark.defense_client import DefenseTarget, RoleCredential  # noqa: E402
from opsark.defense_models import DefenseManifest, DefenseRequest  # noqa: E402
from opsark.defense_policy import DefensePolicy  # noqa: E402
from opsark.defense_store import (  # noqa: E402
    AliasMap,
    DefenseAlias,
    DefenseConflict,
    DefenseStore,
    UsageClaim,
)
from opsark.models import HostPublic  # noqa: E402

EXIT_CODES = {"intent": 81, "sendable": 82, "accepted_before_receipt_commit": 83}


def _root_document(root):
    def encode(value):
        if isinstance(value, DefenseRequest):
            return {"request": value.model_dump(mode="json")}
        if isinstance(value, DefenseManifest):
            return {"manifest": value.model_dump(mode="json")}
        if isinstance(value, datetime):
            return {"datetime": value.isoformat()}
        return value

    return {
        "mode": root.mode,
        "revision": root.revision,
        "records": {
            rid: {key: encode(value) for key, value in row.items()}
            for rid, row in root.records.items()
        },
        "sent": root.sent,
    }


def _restore_root(root, document):
    def decode(value):
        if not isinstance(value, dict):
            return value
        if "request" in value:
            return DefenseRequest.model_validate_json(json.dumps(value["request"]))
        if "manifest" in value:
            return DefenseManifest.model_validate_json(json.dumps(value["manifest"]))
        if "datetime" in value:
            return datetime.fromisoformat(value["datetime"])
        raise AssertionError("Unexpected synthetic Root value")

    root.mode, root.revision = document["mode"], document["revision"]
    root.records = {
        rid: {key: decode(value) for key, value in row.items()}
        for rid, row in document["records"].items()
    }
    root.sent = [tuple(row) for row in document["sent"]]


def _target_document(target):
    return {
        "public": target.host.public.model_dump(mode="json"),
        "collector": str(target.host.key_file),
        "collector_pin": str(target.host.known_hosts_file),
        "roles": [
            {
                "username": role.username,
                "port": role.port,
                "key_file": str(role.key_file),
                "known_hosts_file": str(role.known_hosts_file),
                "trusted_hosts_digest": role.trusted_hosts_digest,
            }
            for role in (target.readonly, target.observe, target.control)
        ],
        "scope": target.root_scope_sha256,
        "policy": target.root_policy_sha256,
        "boot": target.boot_ref,
        "binding": target.binding_ref,
        "other_keys": [str(path) for path in target.other_key_files],
    }


def _restore_target(document):
    host = HostConfig(
        HostPublic.model_validate(document["public"]),
        Path(document["collector"]),
        Path(document["collector_pin"]),
    )
    roles = [
        RoleCredential(
            row["username"],
            row["port"],
            Path(row["key_file"]),
            Path(row["known_hosts_file"]),
            row["trusted_hosts_digest"],
        )
        for row in document["roles"]
    ]
    return DefenseTarget(
        host,
        *roles,
        document["scope"],
        document["policy"],
        document["boot"],
        document["binding"],
        tuple(Path(path) for path in document["other_keys"]),
    )


def _immutable_images(path, rid):
    """Compare original bytes/rowids, not a projection that could hide replacement."""
    with closing(sqlite3.connect(path)) as database, database:
        tables = (
            "defense_authorizations",
            "defense_usage",
            "defense_ai_intents",
            "defense_ai_results",
            "defense_sources",
            "defense_mode_ack",
            "defense_mode_ack_history",
            "defense_mode_query_bindings",
            "defense_observation_intents",
            "defense_target_latches",
        )
        images = {
            table: database.execute("SELECT rowid,* FROM " + table + " ORDER BY rowid").fetchall()  # noqa: S608 -- fixed literal table allowlist.
            for table in tables
        }
        images["requests"] = database.execute(
            "SELECT rowid,* FROM defense_requests WHERE rid=? ORDER BY op", (rid,)
        ).fetchall()
        images["transaction_identity"] = database.execute(
            "SELECT rowid,rid,kind,host_id,defense_scope,context_json,context_sha256,owner,"
            "deadline_at,cursor_rid,created_at,manifest_sha256,manifest_json,action_id "
            "FROM defense_transactions ORDER BY rowid"
        ).fetchall()
        return images


def _charge_synthetic_ai_intent(h, cursor):
    transaction = h.store.transaction(cursor)
    source = h.store.cursor_source(cursor, host_scope=scope_for(h.target.host.public))
    source_key = "a" * 64
    h.store.save_source(
        source_key,
        source,
        alias_map=AliasMap(
            aliases=(
                DefenseAlias(
                    candidate_alias="candidate-1",
                    evidence_alias="evidence-1",
                    source_ref=SOURCE,
                    evidence_sha256=EVIDENCE,
                ),
            )
        ),
    )
    usage = UsageClaim(
        intent_key="b" * 64,
        kind="ai",
        grant_ref="a" * 32,
        max_per_day=1,
        max_total=1,
        provider_fingerprint="c" * 64,
    )
    h.store.begin_ai_usage(
        cursor,
        source_key=source_key,
        context=transaction.context,
        owner=transaction.owner,
        usage=usage,
        analysis_id="d" * 32,
        input_digest="e" * 64,
        now=NOW,
    )
    return usage.intent_key


@pytest.mark.parametrize("boundary", tuple(EXIT_CODES))
def test_real_process_exit_loses_apply_permit_and_only_queries_same_original(
    harness, boundary, tmp_path
):
    h = harness
    revision, cursor, _, action = ready(h)
    rid = action["request_id"]
    ai_intent = _charge_synthetic_ai_intent(h, cursor["request_id"])
    ai_before = h.store.usage(ai_intent)
    automation_before = h.automation.status()
    original_images = _immutable_images(h.store.path, rid)
    with closing(sqlite3.connect(h.store.path)) as database, database:
        original_observations = database.execute(
            "SELECT rowid,* FROM defense_observations ORDER BY rowid"
        ).fetchall()
    payload = {
        "boundary": boundary,
        "directory": str(tmp_path),
        "rid": rid,
        "revision": revision,
        "manifest": action["manifest"]["sha256"],
        "target": _target_document(h.target),
        "root": _root_document(h.root),
        "policy": h.service.policy.model_dump(mode="json"),
        "automation_scope": h.automation.supplemental_scope,
    }
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("OPSARK_")
    }
    result = subprocess.run(  # noqa: S603 -- fixed owned script, synthetic references only over stdin.
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        input=json.dumps(payload).encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=tmp_path,
        env=environment,
        timeout=20,
        check=False,
    )
    error = tmp_path / "child-error.json"
    assert result.returncode == EXIT_CODES[boundary], (
        json.loads(error.read_text()) if error.exists() else "child_import_failed"
    )
    marker = json.loads((tmp_path / "crash-boundary.json").read_text())
    assert marker["boundary"] == boundary and marker["pid"] != os.getpid()
    store = DefenseStore(h.store.path)
    metadata = store.request_metadata(rid, "apply")
    assert metadata.dispatch_phase == ("intent" if boundary == "intent" else "sendable")
    assert metadata.reply_sha256 is None
    approval = store.approval_record(rid)
    assert approval is not None
    assert approval.dispatch_state == ("recorded" if boundary == "intent" else "used")
    execution = store.execution_usage(rid)
    assert execution is not None
    assert execution.state == ("reserved" if boundary == "intent" else "consumed")
    assert store.usage(ai_intent) == ai_before
    frozen = _immutable_images(store.path, rid)
    assert frozen["transaction_identity"] == original_images["transaction_identity"]
    assert all(row in frozen["requests"] for row in original_images["requests"])
    if boundary == "accepted_before_receipt_commit":
        _restore_root(h.root, json.loads((tmp_path / "accepted-root.json").read_text()))
    old_owner = store.transaction(rid).owner
    automation = AutomationStore(
        h.automation.path, h.automation.policy, supplemental_scope=h.automation.supplemental_scope
    )
    restarted = DefenseService(
        h.service.settings,
        h.service.targets,
        store,
        automation,
        policy=h.service.policy,
        invoker=h.root,
        clock=lambda: NOW,
    )
    assert restarted.owner != old_owner
    with pytest.raises(DefenseConflict) if boundary == "intent" else nullcontext():
        assert (
            store.begin_sendable(
                rid, "apply", context=store.transaction(rid).context, owner=restarted.owner, now=NOW
            )
            is None
        )
    sent_before = tuple(h.root.sent)
    for _ in range(2):
        response = restarted.apply(
            "fixture",
            rid,
            ApplyRequest(
                expected_manifest_sha256=action["manifest"]["sha256"],
                expected_mode_revision=revision,
                confirm_execute=True,
            ),
        )
        assert response["request_id"] == rid
        assert response["phase"] == (
            "active" if boundary == "accepted_before_receipt_commit" else "ready"
        )
    assert h.root.sent[len(sent_before) :] == [("query", rid), ("query", rid)]
    assert sum(op == "apply" for op, _ in h.root.sent) == int(
        boundary == "accepted_before_receipt_commit"
    )
    assert _immutable_images(store.path, rid) == frozen
    assert automation.status() == automation_before
    assert store.usage(ai_intent) == ai_before
    assert len([row for row in store.transactions() if row.kind == "action"]) == 1
    with closing(sqlite3.connect(store.path)) as database, database:
        retained = database.execute(
            "SELECT rowid,* FROM defense_observations ORDER BY rowid"
        ).fetchall()
    assert retained[: len(original_observations)] == original_observations
    assert len(retained) == len(original_observations) + 2


def _child():
    payload = json.loads(sys.stdin.buffer.read(65537))
    directory = Path(payload["directory"])
    boundary = payload["boundary"]
    assert boundary in EXIT_CODES and directory.is_absolute()
    target = _restore_target(payload["target"])
    root = FakeRoot(target, lambda: NOW)
    _restore_root(root, payload["root"])
    store = DefenseStore(directory / "security.sqlite3")
    automation = AutomationStore(
        directory / "automation.sqlite3",
        ControlPolicy(),
        supplemental_scope=payload["automation_scope"],
    )
    service = DefenseService(
        Settings(directory, "synthetic-process-crash-token-only"),
        {"fixture": target},
        store,
        automation,
        policy=DefensePolicy.model_validate_json(json.dumps(payload["policy"])),
        invoker=root,
        clock=lambda: NOW,
    )

    def stop():
        with (directory / "crash-boundary.json").open("x", encoding="ascii") as output:
            json.dump({"pid": os.getpid(), "boundary": boundary}, output)
        os._exit(EXIT_CODES[boundary])

    original_save, original_begin, original_reply = (
        store.save_request,
        store.begin_sendable,
        store.record_reply,
    )

    def save(rid, request):
        result = original_save(rid, request)
        if request.op == "apply" and boundary == "intent":
            stop()
        return result

    def begin(rid, op, **options):
        permit = original_begin(rid, op, **options)
        if op == "apply" and boundary == "sendable":
            assert permit is not None
            stop()
        return permit

    def record(rid, op, reply, **options):
        if op == "apply" and boundary == "accepted_before_receipt_commit":
            assert root.records[rid]["state"] == "active" and reply.state == "active"
            with (directory / "accepted-root.json").open("x", encoding="ascii") as output:
                json.dump(_root_document(root), output)
            stop()
        return original_reply(rid, op, reply, **options)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(store, "save_request", save)
        monkeypatch.setattr(store, "begin_sendable", begin)
        monkeypatch.setattr(store, "record_reply", record)
        service.apply(
            "fixture",
            payload["rid"],
            ApplyRequest(
                expected_manifest_sha256=payload["manifest"],
                expected_mode_revision=payload["revision"],
                confirm_execute=True,
            ),
        )
    return 1


if __name__ == "__main__":
    assert sys.argv[1:] == ["--child"]
    try:
        raise SystemExit(_child())
    except Exception as error:
        import traceback

        frames = traceback.extract_tb(error.__traceback__)
        with (Path.cwd() / "child-error.json").open("w", encoding="ascii") as output:
            json.dump(
                {
                    "type": type(error).__name__,
                    "frames": [{"function": row.name, "line": row.lineno} for row in frames],
                },
                output,
            )
        raise SystemExit(1) from None
