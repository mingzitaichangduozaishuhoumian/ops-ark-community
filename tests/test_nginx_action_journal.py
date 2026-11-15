"""Exercise durable Nginx action receipts using real Linux filesystem semantics."""

import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "deploy" / "nginx" / "action_journal.py"
SPEC = importlib.util.spec_from_file_location("opsark_action_journal_test", MODULE_PATH)
assert SPEC and SPEC.loader
journal_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(journal_tool)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Actual Linux root ownership, no-atime reads and advisory directory locks",
)

PLAN_ID = "a" * 32
APPROVAL_ID = "b" * 32
PLAN_SHA = "c" * 64
SOURCE_SHA = "d" * 64
CANDIDATE_SHA = "e" * 64
RUNTIME_SHA = "f" * 64
ACTION_ID = journal_tool.action_id(PLAN_ID)
_CHILD_SETUP = """
import importlib.util
import os
import signal
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("journal_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
journal = module.ActionJournal(Path(sys.argv[2]))
"""


@pytest.fixture
def private_journal():
    # /tmp cannot satisfy the actual root-owned, non-writable ancestor policy.
    with tempfile.TemporaryDirectory(prefix=".opsark-action-journal-", dir="/root") as root:
        directory = Path(root) / "actions"
        directory.mkdir(mode=0o700)
        yield directory, journal_tool.ActionJournal(directory)


def _begin(transaction, approval=APPROVAL_ID):
    return transaction.begin(PLAN_ID, "apply", approval, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)


def _child(directory, script, *arguments):
    return subprocess.run(  # noqa: S603 -- fixed Python child and locally created fixture.
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            _CHILD_SETUP + script,
            str(MODULE_PATH),
            str(directory),
            *arguments,
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )


def _stat(path):
    info = path.stat()
    return info.st_ino, info.st_size, info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns


def _disk_identity(directory, name="fixture.conf"):
    published = directory.parent / name
    published.write_bytes(b"isolated fixture\n")
    published.chmod(0o644)
    info = published.stat()
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


def test_observed_publication_proves_renamed_inode_without_rewriting_result(private_journal):
    directory, owner = private_journal
    staged = _disk_identity(directory)
    source = directory.parent / "fixture.conf"
    dest = source.with_name("owned-target.conf")
    with owner.locked() as tx:
        tx.begin(
            PLAN_ID,
            "apply",
            APPROVAL_ID,
            PLAN_SHA,
            SOURCE_SHA,
            CANDIDATE_SHA,
            staged_identity=staged,
        )
        source.rename(dest)
        tx.finish(ACTION_ID, "unknown")
    terminal = directory / f"{ACTION_ID}.result.json"
    historical = terminal.read_bytes()
    renamed = {**staged, "ctime_ns": dest.stat().st_ctime_ns}
    with owner.locked() as tx:
        with pytest.raises(journal_tool.JournalError):
            tx.observe_publication(ACTION_ID, {**renamed, "ino": renamed["ino"] + 1}, RUNTIME_SHA)
        tx.observe_publication(ACTION_ID, renamed, RUNTIME_SHA)
        assert tx.publication(ACTION_ID)["disk_identity"] == renamed
        with pytest.raises(journal_tool.JournalError):
            tx.reconcile(ACTION_ID)
        observed = tx.reconcile(ACTION_ID, "disk_published_live_previous")
    assert owner.status(ACTION_ID) == observed
    assert observed["status"] == "unknown"
    assert terminal.read_bytes() == historical


@pytest.mark.parametrize("action", ["apply", "restore"])
def test_unchanged_observation_keeps_original_result_and_releases_slot(private_journal, action):
    directory, journal = private_journal
    stage = _disk_identity(directory, "stage.conf")
    source = _disk_identity(directory, "source.conf")
    identifier = journal_tool.action_id(PLAN_ID, action)
    with journal.locked() as transaction:
        transaction.begin(
            PLAN_ID, action, APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA, staged_identity=stage
        )
        with pytest.raises(journal_tool.JournalError):
            transaction.reconcile_unchanged(identifier, source, RUNTIME_SHA)
        result = transaction.finish(identifier, "unknown")
    original_result = _stat(directory / f"{identifier}.result.json")
    with journal.locked() as transaction:
        assert transaction.has_action(action)
        closed = transaction.reconcile_unchanged(identifier, source, RUNTIME_SHA)
        assert closed == {**result, "reconciliation_status": "unchanged_from_preview"}
        assert transaction.reconcile_unchanged(identifier, source, RUNTIME_SHA) == closed
        assert not transaction.has_action(action)
        assert transaction.publication(identifier) is None
        with pytest.raises(journal_tool.JournalError):
            transaction.reconcile_unchanged(identifier, source, PLAN_SHA)
        with pytest.raises(journal_tool.JournalError):
            transaction.begin(PLAN_ID, action, APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)
        assert (
            transaction.begin("f" * 32, action, APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)[
                "status"
            ]
            == "unknown"
        )
        assert transaction.has_action(action)
    assert journal.status(identifier) == closed
    assert _stat(directory / f"{identifier}.result.json") == original_result


@pytest.mark.parametrize("blocker", ["legacy", "same_inode", "publication", "activation"])
def test_unchanged_observation_requires_new_unpublished_staged_evidence(private_journal, blocker):
    directory, journal = private_journal
    stage = _disk_identity(directory, "stage.conf")
    source = stage if blocker == "same_inode" else _disk_identity(directory, "source.conf")
    with journal.locked() as transaction:
        transaction.begin(
            PLAN_ID,
            "apply",
            APPROVAL_ID,
            PLAN_SHA,
            SOURCE_SHA,
            CANDIDATE_SHA,
            staged_identity=None if blocker == "legacy" else stage,
        )
        if blocker in {"publication", "activation"}:
            transaction.publish(ACTION_ID, stage, RUNTIME_SHA)
        if blocker == "activation":
            transaction.mark_activation(ACTION_ID)
        result = transaction.finish(ACTION_ID, "unknown")
    with journal.locked() as transaction:
        with pytest.raises(journal_tool.JournalError):
            transaction.reconcile_unchanged(ACTION_ID, source, RUNTIME_SHA)
        assert transaction.has_action("apply")
    assert journal.status(ACTION_ID) == result


def test_no_start_tombstone_is_durable_and_does_not_consume_action_slot(private_journal):
    directory, journal = private_journal
    with journal.locked() as transaction:
        assert not transaction.unstarted(ACTION_ID)
        transaction.close_unstarted(PLAN_ID, "apply", PLAN_SHA)
    marker = directory / f"{ACTION_ID}.not_started.json"
    original = _stat(marker)
    with journal.locked() as transaction:
        assert transaction.unstarted(ACTION_ID)
        assert not transaction.has_action("apply")
        transaction.close_unstarted(PLAN_ID, "apply", PLAN_SHA)
        with pytest.raises(journal_tool.JournalError):
            transaction.close_unstarted(PLAN_ID, "apply", RUNTIME_SHA)
        with pytest.raises(journal_tool.JournalError):
            _begin(transaction)
        assert _stat(marker) == original
        assert (
            transaction.begin("f" * 32, "apply", APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)[
                "status"
            ]
            == "unknown"
        )
        assert transaction.has_action("apply")
    assert journal.status(ACTION_ID) is None


@pytest.mark.parametrize("marked_activation", [False, True])
def test_only_unactivated_publication_can_be_sealed_as_live_previous(
    private_journal, marked_activation
):
    directory, journal = private_journal
    with journal.locked() as transaction:
        _begin(transaction)
        transaction.publish(ACTION_ID, _disk_identity(directory), RUNTIME_SHA)
        if marked_activation:
            transaction.mark_activation(ACTION_ID)
        original = transaction.finish(ACTION_ID, "unknown")
    with journal.locked() as transaction:
        assert transaction.activation_pending(ACTION_ID) is marked_activation
        assert transaction.has_action("apply")
        if marked_activation:
            with pytest.raises(journal_tool.JournalError):
                transaction.reconcile(ACTION_ID, "disk_published_live_previous")
            assert transaction.reconcile(ACTION_ID)["reconciliation_status"] == "verified"
        else:
            observed = transaction.reconcile(ACTION_ID, "disk_published_live_previous")
            assert observed == {**original, "reconciliation_status": "disk_published_live_previous"}
            assert transaction.reconcile(ACTION_ID, "verified") == observed
            assert journal.status(ACTION_ID) == observed


@pytest.mark.parametrize("marked_activation", [False, True])
def test_disk_restore_can_only_be_reconciled_without_activation(private_journal, marked_activation):
    directory, journal = private_journal
    identifier = journal_tool.action_id(PLAN_ID, "restore")
    with journal.locked() as transaction:
        transaction.begin(PLAN_ID, "restore", APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)
        transaction.publish(identifier, _disk_identity(directory), RUNTIME_SHA)
        if marked_activation:
            transaction.mark_activation(identifier)
    with journal.locked() as transaction:
        original = transaction.status(identifier)
        with pytest.raises(journal_tool.JournalError):
            transaction.reconcile(identifier)
        if marked_activation:
            with pytest.raises(journal_tool.JournalError):
                transaction.reconcile_disk_restore(identifier)
        else:
            with pytest.raises(journal_tool.JournalError):
                transaction.reconcile_reloaded_restore(identifier)
            reconciled = transaction.reconcile_disk_restore(identifier)
            assert reconciled == {**original, "reconciliation_status": "verified"}
            assert journal.status(identifier) == reconciled


def test_reloaded_restore_reconciliation_is_bound_to_the_original_activation(private_journal):
    directory, journal = private_journal
    identifier = journal_tool.action_id(PLAN_ID, "restore")
    with journal.locked() as transaction:
        transaction.begin(PLAN_ID, "restore", APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA)
        transaction.publish(identifier, _disk_identity(directory), RUNTIME_SHA)
        transaction.mark_activation(identifier)
    original = journal.status(identifier)
    with journal.locked() as transaction:
        observed = transaction.reconcile_reloaded_restore(identifier)
        assert observed == {**original, "reconciliation_status": "verified"}
        assert transaction.reconcile_reloaded_restore(identifier) == observed
    assert journal.status(identifier) == observed
    activation = json.loads((directory / f"{identifier}.activation.json").read_bytes())
    path = directory / f"{identifier}.reconciliation.json"
    record = json.loads(path.read_bytes())
    assert record["activation_sha256"] == activation["activation_sha256"]
    record.pop("reconciliation_sha256")
    record["activation_sha256"] = "0" * 64
    record["reconciliation_sha256"] = journal_tool._digest(record)
    path.write_bytes(journal_tool._canonical(record) + b"\n")
    with pytest.raises(journal_tool.JournalError):
        journal.status(identifier)


def test_status_and_same_plan_replay_preserve_the_original_receipt(private_journal):
    directory, journal = private_journal
    assert journal.status(ACTION_ID) is None
    assert not list(directory.iterdir())

    with journal.locked() as transaction:
        assert not transaction.has_action("apply")
        pending = _begin(transaction)
        assert pending["status"] == "unknown"
        assert transaction.has_action("apply")
        assert not transaction.has_action("restore")
        assert journal.status(ACTION_ID) == pending
        verified = transaction.finish(ACTION_ID, "verified")
        with pytest.raises(journal_tool.JournalError):
            transaction.finish(ACTION_ID, "unknown")

    assert set(verified) == {
        "schema_version",
        "action_id",
        "action",
        "status",
        "source_sha256",
        "candidate_sha256",
    }
    assert verified["status"] == "verified"
    original = {path: path.read_bytes() for path in directory.iterdir()}
    assert len(original) == 2
    for path in original:
        # Give an ordinary file open/read a reason to advance atime on relatime mounts.
        os.utime(path, ns=(1, path.stat().st_mtime_ns))
    metadata = {path: _stat(path) for path in original}

    with journal.locked() as transaction:
        assert transaction.has_action("apply")
        with pytest.raises(journal_tool.JournalError):
            _begin(transaction, approval="1" * 32)
    assert journal.status(ACTION_ID) == verified
    assert {path: _stat(path) for path in directory.iterdir()} == metadata
    assert {path: path.read_bytes() for path in directory.iterdir()} == original


def test_other_process_cannot_take_lock_but_can_read_pending_action(private_journal):
    directory, journal = private_journal
    with journal.locked() as transaction:
        _begin(transaction)
        child = _child(
            directory,
            """
assert journal.status(sys.argv[3])["status"] == "unknown"
try:
    with journal.locked():
        raise AssertionError("second process acquired the journal lock")
except module.JournalError as error:
    assert "holds the journal lock" in str(error)
""",
            ACTION_ID,
        )
        assert child.returncode == 0, child.stderr.decode(errors="replace")
        assert transaction.finish(ACTION_ID, "verified")["status"] == "verified"


def test_killed_process_cannot_replay_or_complete_the_durable_intent(private_journal):
    directory, journal = private_journal
    child = _child(
        directory,
        """
with journal.locked() as transaction:
    transaction.begin(sys.argv[3], "apply", sys.argv[4], *sys.argv[5:])
    os.kill(os.getpid(), signal.SIGKILL)
""",
        PLAN_ID,
        APPROVAL_ID,
        PLAN_SHA,
        SOURCE_SHA,
        CANDIDATE_SHA,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr.decode(errors="replace")

    pending = journal.status(ACTION_ID)
    assert pending is not None and pending["status"] == "unknown"
    assert pending["action_id"] == ACTION_ID
    with journal.locked() as transaction:
        assert transaction.status(journal_tool.action_id("2" * 32)) is None
        assert transaction.has_action("apply")
        with pytest.raises(journal_tool.JournalError):
            _begin(transaction, approval="2" * 32)
        with pytest.raises(journal_tool.JournalError):
            transaction.finish(ACTION_ID, "verified")
    assert journal.status(ACTION_ID) == pending
    assert not (directory / f"{ACTION_ID}.result.json").exists()


@pytest.mark.parametrize("damage", ["modified_intent", "hardlink", "missing_intent"])
def test_invalid_evidence_cannot_be_read_or_replayed(private_journal, damage):
    directory, journal = private_journal
    with journal.locked() as transaction:
        _begin(transaction)
        transaction.finish(ACTION_ID, "verified")

    intent = directory / f"{ACTION_ID}.intent.json"
    if damage == "modified_intent":
        intent.write_bytes(intent.read_bytes().replace(SOURCE_SHA.encode(), b"1" * 64))
    elif damage == "hardlink":
        (directory / "alias.json").hardlink_to(intent)
    else:
        intent.unlink()
    names = sorted(path.name for path in directory.iterdir())

    with pytest.raises(journal_tool.JournalError):
        journal.status(ACTION_ID)
    with journal.locked() as transaction:
        with pytest.raises(journal_tool.JournalError):
            _begin(transaction)
        with pytest.raises(journal_tool.JournalError):
            transaction.has_action("apply")
    assert sorted(path.name for path in directory.iterdir()) == names


def test_workspace_gate_rejects_oversized_or_unexpected_inventory(private_journal, monkeypatch):
    directory, journal = private_journal
    with journal.locked() as transaction:
        _begin(transaction)
        transaction.finish(ACTION_ID, "verified")
        with monkeypatch.context() as budget:
            budget.setattr(journal_tool, "_MAX_ENTRIES", 1)
            with pytest.raises(journal_tool.JournalError, match="inspection budget"):
                transaction.has_action("apply")
        # A pre-publication crash may leave an unfinished entry. Refuse to open a new action.
        (directory / ".pending-stale").write_text("incomplete", encoding="ascii")
        with pytest.raises(journal_tool.JournalError, match="Unexpected action journal entry"):
            transaction.has_action("apply")
        assert transaction.status(ACTION_ID)["status"] == "verified"


def test_killed_published_action_has_independent_reconciliation_receipt(private_journal):
    directory, journal = private_journal
    identity = _disk_identity(directory)
    child = _child(
        directory,
        """
import json

with journal.locked() as transaction:
    pending = transaction.begin(sys.argv[3], "apply", *sys.argv[4:8])
    transaction.publish(pending["action_id"], json.loads(sys.argv[8]), sys.argv[9])
    os.kill(os.getpid(), signal.SIGKILL)
""",
        PLAN_ID,
        APPROVAL_ID,
        PLAN_SHA,
        SOURCE_SHA,
        CANDIDATE_SHA,
        json.dumps(identity),
        RUNTIME_SHA,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr.decode(errors="replace")
    previous = journal.status(ACTION_ID)
    assert previous is not None and previous["status"] == "unknown"
    before = {path: path.read_bytes() for path in directory.iterdir()}
    assert len(before) == 2
    with journal.locked() as transaction:
        publication = transaction.publication(ACTION_ID)
        assert publication is not None
        assert publication["disk_identity"] == identity
        assert publication["runtime_sha256"] == RUNTIME_SHA
        assert transaction.intent_binding(ACTION_ID) == {
            "plan_id": PLAN_ID,
            "approval_id": APPROVAL_ID,
            "plan_sha256": PLAN_SHA,
            "action": "apply",
            "source_sha256": SOURCE_SHA,
            "candidate_sha256": CANDIDATE_SHA,
        }
        with pytest.raises(journal_tool.JournalError):
            transaction.publish(ACTION_ID, identity, RUNTIME_SHA)
        reconciled = transaction.reconcile(ACTION_ID)
        assert transaction.has_action("apply")
        assert transaction.reconcile(ACTION_ID) == reconciled
    assert reconciled == {**previous, "reconciliation_status": "verified"}
    assert journal.status(ACTION_ID) == reconciled
    assert not (directory / f"{ACTION_ID}.result.json").exists()
    assert {path: path.read_bytes() for path in before} == before
    assert len(list(directory.iterdir())) == 3


def test_reconciliation_requires_unknown_published_apply(private_journal):
    directory, journal = private_journal
    identity = _disk_identity(directory)
    with journal.locked() as transaction:
        _begin(transaction)
        with pytest.raises(journal_tool.JournalError):
            transaction.publish(ACTION_ID, {**identity, "ino": True}, RUNTIME_SHA)
        with pytest.raises(journal_tool.JournalError):
            transaction.publish(ACTION_ID, {**identity, "path": 1}, RUNTIME_SHA)
        assert transaction.publication(ACTION_ID) is None
        transaction.publish(ACTION_ID, identity, RUNTIME_SHA)
        with pytest.raises(journal_tool.JournalError):
            transaction.publish(ACTION_ID, identity, RUNTIME_SHA)
        with pytest.raises(journal_tool.JournalError):
            transaction.reconcile(ACTION_ID)
        transaction.finish(ACTION_ID, "verified")

        without_publication = transaction.begin(
            "1" * 32, "apply", APPROVAL_ID, PLAN_SHA, SOURCE_SHA, CANDIDATE_SHA
        )
        transaction.finish(without_publication["action_id"], "unknown")
        restore = transaction.begin(
            PLAN_ID, "restore", APPROVAL_ID, PLAN_SHA, CANDIDATE_SHA, SOURCE_SHA
        )
        transaction.publish(restore["action_id"], identity, RUNTIME_SHA)
        transaction.finish(restore["action_id"], "unknown")
    with journal.locked() as transaction:
        for identifier in (ACTION_ID, without_publication["action_id"], restore["action_id"]):
            with pytest.raises(journal_tool.JournalError):
                transaction.reconcile(identifier)
    assert not list(directory.glob("*.reconciliation.json"))


@pytest.mark.parametrize("damage", ["resealed_publication", "missing_result"])
def test_reconciliation_is_bound_to_publication_and_exact_original_result(private_journal, damage):
    directory, journal = private_journal
    with journal.locked() as transaction:
        _begin(transaction)
        transaction.publish(ACTION_ID, _disk_identity(directory), RUNTIME_SHA)
        transaction.finish(ACTION_ID, "unknown")
    with journal.locked() as transaction:
        receipt = transaction.reconcile(ACTION_ID)
    assert receipt["status"] == "unknown" and receipt["reconciliation_status"] == "verified"

    if damage == "resealed_publication":
        path = directory / f"{ACTION_ID}.publication.json"
        replacement = json.loads(path.read_bytes())
        replacement.pop("publication_sha256")
        replacement["runtime_sha256"] = "3" * 64
        replacement["publication_sha256"] = journal_tool._digest(replacement)
        path.write_bytes(journal_tool._canonical(replacement) + b"\n")
    else:
        (directory / f"{ACTION_ID}.result.json").unlink()
    with pytest.raises(journal_tool.JournalError):
        journal.status(ACTION_ID)
    with journal.locked() as transaction, pytest.raises(journal_tool.JournalError):
        transaction.has_action("apply")
