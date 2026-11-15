"""Check real filesystem and journal behavior with injected runtime callbacks."""

import importlib
import io
import json
import os
import stat
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux fixture trust rules")
CREATED = datetime(2026, 11, 5, 2, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
RUNTIME = "b" * 64
OTHER_RUNTIME = "c" * 64


class Interrupted(BaseException):
    """Simulate process interruption without permitting normal result publication."""


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.import_module("deploy.nginx.fixture_action")


def prepare(lab, suffix=""):
    action, snapshot = lab.action, lab.action.config_snapshot
    plan = lab.workspace / ("plan" + suffix)
    approval = lab.workspace / ("approval" + suffix)
    prepared = snapshot.prepare(
        lab.backup, lab.candidate, action.CANDIDATE_DIGEST, plan, policy=lab.policy, now=CREATED
    )
    proof = snapshot.approve_plan(
        plan,
        IMAGE,
        prepared["plan_id"],
        action.CANDIDATE_DIGEST,
        approval,
        confirm=True,
        policy=lab.policy,
        now=CREATED,
    )
    return approval, proof["approval_id"]


@pytest.fixture
def fixture_lab(module, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("Actual isolated Nginx disk action requires root")
    snapshot = module.config_snapshot
    monkeypatch.setattr(snapshot, "_fixture_syntax", lambda _data, _image: "passed")
    with tempfile.TemporaryDirectory(dir="/root", prefix="opsark-fixture-action-test-") as tmp:
        workspace = Path(tmp)
        marker = workspace / module.WORKSPACE_MARKER
        marker.write_bytes(module.WORKSPACE_MARKER_CONTENT)
        marker.chmod(0o600)
        directory = workspace / "etc/nginx/conf.d"
        directory.mkdir(mode=0o700, parents=True)
        (workspace / "etc/machine-id").write_text(uuid.uuid4().hex + "\n", encoding="ascii")
        site = directory / module.TARGET_NAME
        site.write_bytes(module.ORIGINAL)
        site.chmod(0o640)
        candidate = workspace / "candidate.conf"
        candidate.write_bytes(module.CANDIDATE)
        candidate.chmod(0o600)
        (workspace / "actions").mkdir(mode=0o700)
        policy = module.fixture_policy(workspace)
        backup = workspace / "backup"
        snapshot.capture(site, snapshot._sha(module.ORIGINAL), backup, policy=policy)
        lab = SimpleNamespace(
            action=module,
            workspace=workspace,
            site=site,
            candidate=candidate,
            policy=policy,
            backup=backup,
        )
        lab.approval, lab.approval_id = prepare(lab)
        lab.id = module.action_id_for_approval(workspace, lab.approval)
        yield lab


def apply(lab, reload_and_verify, **overrides):
    options = {"confirm": True, "now": CREATED, **overrides}
    return lab.action.apply_fixture(
        lab.workspace,
        lab.approval,
        lab.approval_id,
        lab.action.CANDIDATE_DIGEST,
        reload_and_verify=reload_and_verify,
        **options,
    )


def observe(lab, identifier=None):
    return lab.action.inspect_action(lab.workspace, identifier or lab.id)


def unexpected():
    pytest.fail("a refused or recorded action attempted a runtime operation")


@pytest.mark.parametrize("reason", ["expired", "preflight", "drift", "unconfirmed"])
def test_refused_action_never_creates_an_intent(fixture_lab, reason):
    lab = fixture_lab
    options = {}
    if reason == "expired":
        options["now"] = CREATED + timedelta(minutes=10)
    elif reason == "preflight":
        options["preflight"] = lambda: False
    elif reason == "drift":
        lab.site.write_bytes(lab.action.ORIGINAL + b"# independent edit\n")
    else:
        options["confirm"] = False
    content, identity = lab.site.read_bytes(), lab.site.stat()
    with pytest.raises(lab.action.config_snapshot.SnapshotError):
        apply(lab, unexpected, **options)
    assert observe(lab)["status"] == "missing"
    assert not list((lab.workspace / "actions").glob("*.json"))
    assert lab.site.read_bytes() == content and lab.site.stat().st_ino == identity.st_ino


def test_verified_action_is_an_atomic_mode_preserving_single_write(fixture_lab, capsys):
    lab = fixture_lab
    original = lab.site.stat()
    calls = []

    def reload():
        calls.append("reload")
        pending = observe(lab)
        assert pending["status"] == "unknown" and pending["disk_status"] == "candidate"
        return True

    receipt = apply(lab, reload, preflight=lambda: True, runtime_fingerprint=lambda: RUNTIME)
    published = lab.site.stat()
    assert published.st_ino != original.st_ino
    assert (published.st_uid, published.st_gid) == (original.st_uid, original.st_gid)
    assert stat.S_IMODE(published.st_mode) == 0o640
    assert lab.site.read_bytes() == lab.action.CANDIDATE
    assert receipt["action_id"] == lab.id and receipt["status"] == "verified"
    publication = get_publication(lab)
    assert publication["disk_identity"] == lab.action.config_snapshot._signature(published)
    assert publication["runtime_sha256"] == RUNTIME
    assert apply(lab, unexpected, now=CREATED + timedelta(hours=1)) == observe(lab) == receipt
    assert calls == ["reload"] and lab.site.stat().st_ino == published.st_ino
    output = capsys.readouterr()
    public = json.dumps(receipt) + output.out + output.err
    assert all(secret not in public for secret in (str(lab.workspace), "opsark-candidate"))


@pytest.mark.parametrize("interrupted", [False, True])
def test_unconfirmed_runtime_result_keeps_original_without_replay(fixture_lab, interrupted):
    lab = fixture_lab

    def reload():
        assert lab.site.read_bytes() == lab.action.CANDIDATE
        if interrupted:
            raise Interrupted
        return False

    if interrupted:
        with pytest.raises(Interrupted):
            apply(lab, reload)
    else:
        assert apply(lab, reload)["status"] == "unknown"
    original = observe(lab)
    identity = lab.site.stat()
    assert original["action_id"] == lab.id and original["status"] == "unknown"
    assert original["disk_status"] == "candidate"
    assert apply(lab, unexpected) == original and lab.site.stat().st_ino == identity.st_ino


def test_new_plan_cannot_bypass_original_prewrite_intent(fixture_lab, monkeypatch):
    lab = fixture_lab
    other_approval, other_approval_id = prepare(lab, "-second")

    def interrupt(*_args, **_kwargs):
        raise Interrupted

    with monkeypatch.context() as scoped:
        scoped.setattr(lab.action.os, "replace", interrupt)
        with pytest.raises(Interrupted):
            apply(lab, unexpected)
    prior = observe(lab)
    assert prior["status"] == "unknown" and prior["disk_status"] == "preimage"
    assert apply(lab, unexpected) == prior
    other_id = lab.action.action_id_for_approval(lab.workspace, other_approval)
    assert other_id != lab.id
    with pytest.raises(lab.action.config_snapshot.SnapshotError):
        lab.action.apply_fixture(
            lab.workspace,
            other_approval,
            other_approval_id,
            lab.action.CANDIDATE_DIGEST,
            confirm=True,
            now=CREATED,
            reload_and_verify=unexpected,
        )
    assert observe(lab, other_id)["status"] == "missing" and observe(lab) == prior
    assert lab.site.read_bytes() == lab.action.ORIGINAL


def get_publication(lab):
    journal = lab.action.action_journal.ActionJournal(lab.workspace / "actions")
    with journal.locked() as tx:
        return tx.publication(lab.id)


def interrupt_after_publication(lab):
    def interrupted():
        assert lab.site.read_bytes() == lab.action.CANDIDATE
        assert (lab.workspace / "actions" / (lab.id + ".publication.json")).is_file()
        raise Interrupted

    with pytest.raises(Interrupted):
        apply(lab, interrupted, preflight=lambda: True, runtime_fingerprint=lambda: RUNTIME)
    return observe(lab)


def reconcile(lab, verify_candidate, *, runtime_fingerprint=lambda: RUNTIME):
    return lab.action.reconcile_fixture(
        lab.workspace,
        lab.id,
        runtime_fingerprint=runtime_fingerprint,
        verify_candidate=verify_candidate,
    )


def test_reconcile_adds_independent_evidence_and_never_replays(fixture_lab):
    lab = fixture_lab
    original = interrupt_after_publication(lab)
    assert original["status"] == "unknown" and original["disk_status"] == "candidate"
    journal = lab.workspace / "actions"
    records = {path.name: path.read_bytes() for path in journal.glob("*.json")}
    identity = lab.action.config_snapshot._signature(lab.site.stat())
    assert get_publication(lab)["disk_identity"] == identity
    assert reconcile(lab, unexpected, runtime_fingerprint=lambda: OTHER_RUNTIME) == original
    assert reconcile(lab, lambda: False) == original
    assert {path.name for path in journal.glob("*.json")} == set(records)

    calls = []

    def verify():
        calls.append("read-only runtime observation")
        return True

    result = reconcile(lab, verify)
    assert result == {**original, "reconciliation_status": "verified"}
    assert reconcile(lab, unexpected, runtime_fingerprint=unexpected) == observe(lab) == result
    assert apply(lab, unexpected) == result
    assert calls == ["read-only runtime observation"]
    assert all((journal / name).read_bytes() == data for name, data in records.items())
    assert lab.action.config_snapshot._signature(lab.site.stat()) == identity
    assert len(list(journal.glob("*.json"))) == len(records) + 1


@pytest.mark.parametrize(
    "drift", ["same_bytes_replaced", "mode_during_probe", "runtime_during_probe"]
)
def test_reconcile_refuses_identity_drift_even_with_same_candidate_bytes(fixture_lab, drift):
    lab = fixture_lab
    original = interrupt_after_publication(lab)
    journal = lab.workspace / "actions"
    records = {path.name: path.read_bytes() for path in journal.glob("*.json")}
    current_runtime = RUNTIME

    if drift == "same_bytes_replaced":
        replacement = lab.site.with_suffix(".replacement")
        replacement.write_bytes(lab.action.CANDIDATE)
        replacement.chmod(0o640)
        os.replace(replacement, lab.site)
        verify = unexpected
    else:

        def verify():
            nonlocal current_runtime
            if drift == "mode_during_probe":
                lab.site.chmod(0o600)
            else:
                current_runtime = OTHER_RUNTIME
            return True

    assert reconcile(lab, verify, runtime_fingerprint=lambda: current_runtime) == original
    assert lab.site.read_bytes() == lab.action.CANDIDATE
    assert {path.name: path.read_bytes() for path in journal.glob("*.json")} == records


def test_without_publication_reconciliation_does_not_probe_runtime(fixture_lab):
    lab = fixture_lab
    original = apply(lab, lambda: False)
    assert original["status"] == "unknown" and original["disk_status"] == "candidate"
    assert get_publication(lab) is None
    assert reconcile(lab, unexpected, runtime_fingerprint=unexpected) == original


def test_reconcile_rechecks_the_exact_publication_it_observed(fixture_lab):
    lab = fixture_lab
    original = interrupt_after_publication(lab)
    journal = lab.action.action_journal
    root = lab.workspace / "actions"
    publication_path = root / (lab.id + ".publication.json")
    before = {path.name for path in root.glob("*.json")}

    def verify():
        changed = json.loads(publication_path.read_bytes())
        del changed["publication_sha256"]
        changed["runtime_sha256"] = OTHER_RUNTIME
        sealed = {**changed, "publication_sha256": journal._digest(changed)}
        publication_path.write_bytes(journal._canonical(sealed) + b"\n")
        return True

    assert reconcile(lab, verify) == original
    assert observe(lab) == original and {path.name for path in root.glob("*.json")} == before


def test_runtime_change_during_preflight_refuses_before_intent(fixture_lab):
    lab = fixture_lab
    current = RUNTIME

    def preflight():
        nonlocal current
        current = OTHER_RUNTIME
        return True

    with pytest.raises(lab.action.config_snapshot.SnapshotError):
        apply(lab, unexpected, preflight=preflight, runtime_fingerprint=lambda: current)
    assert observe(lab)["status"] == "missing"
    assert lab.site.read_bytes() == lab.action.ORIGINAL
    assert not list((lab.workspace / "actions").glob("*.json"))


@pytest.mark.parametrize(
    "entry",
    [
        "2 1 8:1 /root /var/fixture rw - ext4 /dev/example rw\n",
        "2 1 8:1 / /var/fixture rw - ext4 /dev/example rw\n",
        "2 1 8:2 / /var/fixture/run rw - ext4 /dev/other rw\n",
        "2 1 8:2 / /var/fixture/run/etc rw - ext4 /dev/other rw\n",
    ],
)
def test_fixture_rejects_mounted_aliases(module, monkeypatch, entry):
    root = "1 0 8:1 / / rw - ext4 /dev/example rw\n"
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: io.StringIO(root + entry))
    with pytest.raises(module.config_snapshot.SnapshotError):
        module._check_mounts(Path("/var/fixture/run"))
