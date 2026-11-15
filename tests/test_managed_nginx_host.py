"""Exercise the host contract and journal over synthetic filesystem/runtime effects."""

import copy
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.nginx import action_journal as journal
from deploy.nginx import config_snapshot as snapshot
from deploy.nginx import managed_action as action
from deploy.nginx import managed_context as context
from deploy.nginx import managed_runtime as runtime
from deploy.nginx import managed_ssh_entry as ssh_entry

TARGET = "conf.d/backend.conf"
ORIGINAL = b"upstream backend { server 127.0.0.1:18081; }\n"
CANDIDATE = b"upstream backend { server 127.0.0.1:18082; }\n"
STATIC = {
    "nginx.conf": b"""user www-data;
pid /run/nginx.pid;
events { worker_connections 32; }
http {
    access_log off;
    include /etc/nginx/conf.d/backend.conf;
    include /etc/nginx/conf.d/sites.conf;
}
""",
    "conf.d/sites.conf": b"""server {
    listen 127.0.0.1:8080;
    server_name affected.example.test;
    location / { proxy_pass http://backend; }
}
server {
    listen 127.0.0.1:8080;
    server_name control.example.test;
    location = /health { default_type text/plain; return 200 "control"; }
}
""",
}


def registration() -> dict:
    return {
        "schema_version": 1,
        "enabled": True,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "target_file": "backend.conf",
        "upstream_name": "backend",
        "from_port": 18081,
        "to_port": 18082,
        "nginx_sha256": "1" * 64,
        "bwrap_sha256": "2" * 64,
        "context_files": ["conf.d/sites.conf", TARGET],
        "sites": [
            {
                "site_id": "target",
                "host": "affected.example.test",
                "listen_port": 8080,
                "path": "/health",
                "before_sha256": "3" * 64,
                "after_sha256": "4" * 64,
            },
            {
                "site_id": "control",
                "host": "control.example.test",
                "listen_port": 8080,
                "path": "/health",
                "before_sha256": "5" * 64,
                "after_sha256": "5" * 64,
            },
        ],
    }


def request(op: str, policy_digest: str, **fields):
    return action.parse_request(
        context.canonical({"schema_version": 1, "op": op, "policy_digest": policy_digest, **fields})
    )


def test_root_policy_closed_and_default_off():
    data = registration()
    policy = context.parse_policy(context.canonical(data))
    assert policy.target == TARGET
    assert context.candidate_for(ORIGINAL, policy) == CANDIDATE
    for changed in (
        {"enabled": False},
        {"target_file": "../../other.conf"},
        {"from_port": True},
        {"to_port": 18081},
        {"context_files": [TARGET]},
        {"extra": "ignored"},
    ):
        with pytest.raises(context.Refused):
            context.parse_policy(context.canonical(data | changed))
    with pytest.raises(context.Refused):
        context.candidate_for(ORIGINAL + ORIGINAL, policy)


def test_protocol_refuses_content_path_duplicates_and_boolean_revision():
    digest = "1" * 64
    accepted = request("prepare", digest, plan_id="a" * 32, mode_revision=1)
    for data in (
        {"path": "/etc/nginx/nginx.conf"},
        {"candidate": "ignored"},
        {"mode_revision": True},
        {"plan_id": "../other"},
        {"op": "exec"},
    ):
        with pytest.raises(context.Refused):
            action.parse_request(context.canonical(accepted | data))
    with pytest.raises(context.Refused):
        action.parse_request(context.canonical(accepted)[:-1] + b',"op":"status"}')


@pytest.mark.parametrize(
    "text",
    [
        b"include /etc/nginx/conf.d/*.conf;",
        b"load_module modules/any.so;",
        b"include /etc/elsewhere.conf;",
    ],
)
def test_unclosed_context_refused(text):
    policy = context.parse_policy(context.canonical(registration()))
    files = {**STATIC, TARGET: ORIGINAL}
    assert context.validate_graph(files, policy) == ("target",)
    files["nginx.conf"] = files["nginx.conf"].replace(
        b"include /etc/nginx/conf.d/sites.conf;", text
    )
    with pytest.raises(context.Refused):
        context.validate_graph(files, policy)


def test_wrong_health_probe_cannot_count_as_affected_route():
    data = registration()
    data["sites"][0]["path"] = "/static"
    policy = context.parse_policy(context.canonical(data))
    files = {**STATIC, TARGET: ORIGINAL}
    files["conf.d/sites.conf"] = files["conf.d/sites.conf"].replace(
        b"location / { proxy_pass http://backend; }",
        b'location / { proxy_pass http://backend; } location = /static { return 200 "ok"; }',
    )
    with pytest.raises(context.Refused, match="scope_changed"):
        context.validate_graph(files, policy)


@contextmanager
def _fake_directory(*_args, **_kwargs):
    yield 11


def test_syntax_checks_exact_candidate_in_private_network_context(monkeypatch, tmp_path):
    policy = context.parse_policy(context.canonical(registration()))
    files = {**STATIC, TARGET: ORIGINAL}
    graph = context.Graph(files, {}, ("target",))
    monkeypatch.setattr(context, "PRIVATE_ROOT", tmp_path)
    monkeypatch.setattr(snapshot, "_directory", _fake_directory)
    monkeypatch.setattr(context, "_binary", lambda *_: {})
    monkeypatch.setattr(
        context,
        "pwd",
        SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=33, pw_gid=33)),
        raising=False,
    )
    monkeypatch.setattr(
        context,
        "grp",
        SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=33)),
        raising=False,
    )
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        root_index = argv.index("/etc/nginx")
        stage = Path(argv[root_index - 1])
        assert (stage / TARGET).read_bytes() == CANDIDATE
        assert (stage / "nginx.conf").read_bytes() == STATIC["nginx.conf"]
        assert "--unshare-net" in argv and "--share-net" not in argv
        assert argv[0] == str(context.BWRAP) and str(context.NGINX) in argv
        assert kwargs["stdout"] == kwargs["stderr"] == context.subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(context.subprocess, "run", run)
    context.syntax_check(policy, graph, CANDIDATE)
    assert len(calls) == 1 and not list(tmp_path.iterdir())


def test_forced_entry_accepts_only_literal_command(monkeypatch):
    calls = []
    monkeypatch.setattr(ssh_entry.sys, "argv", ["entry"])
    monkeypatch.setattr(ssh_entry.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(ssh_entry.os, "execve", lambda *args: calls.append(args))
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "opsark-nginx-action-v1 extra")
    assert ssh_entry.main() == 126 and not calls
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "opsark-nginx-action-v1")
    ssh_entry.main()
    assert calls[0][0] == "/usr/bin/sudo"
    assert calls[0][1] == [
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/bin/python3",
        "-I",
        "-B",
        ssh_entry.ROOT_ACTION,
    ]


class Lab:
    """A bounded memory fixture. Native file publication and HUP are intercepted."""

    def __init__(self, patch):
        self.policy = context.parse_policy(context.canonical(registration()))
        self.files = {**STATIC, TARGET: ORIGINAL}
        self.identities = {
            name: self.identity(raw, i) for i, (name, raw) in enumerate(self.files.items(), 30)
        }
        self.plans, self.backups, self.records = {}, {}, {}
        self.stage = b""
        self.events = []
        self.enabled = True
        self.loaded_candidate = False
        self.interrupted = False
        self.master = SimpleNamespace(sha256="a" * 64, verify=lambda *_: None, reload=self.reload)
        patch.setattr(context, "active_policy", self.active_policy)
        patch.setattr(context, "capture_graph", self.graph)
        patch.setattr(context, "pin_master", self.pin)
        patch.setattr(runtime, "require_started", lambda *_args, **_kwargs: "e" * 64)
        patch.setattr(context, "probe", self.probe)
        patch.setattr(context, "syntax_check", self.syntax)
        patch.setattr(context, "plain_metadata", lambda *_: None)
        patch.setattr(snapshot, "_machine", lambda _: "b" * 64)
        patch.setattr(snapshot, "capture", self.backup)
        patch.setattr(snapshot, "_backup", self.read_backup)
        patch.setattr(snapshot, "_publish", self.publish_plan)
        patch.setattr(snapshot, "_read_bundle", self.read_plan)
        patch.setattr(snapshot, "_directory", _fake_directory)
        patch.setattr(snapshot, "_read", self.read_file)
        patch.setattr(action, "_current_directory", lambda _: None)
        patch.setattr(action, "_plan_capacity", lambda _, **_kwargs: None)
        patch.setattr(action, "_reclaim_previews", lambda *_, **_kwargs: None)
        patch.setattr(action, "_staged", self.staged)
        patch.setattr(action.os, "replace", self.replace)
        patch.setattr(action.os, "fsync", lambda _: None)
        patch.setattr(journal.ActionJournal, "locked", lambda _: self.transaction())
        patch.setattr(journal._Transaction, "has_action", lambda _, name: self.has_action(name))
        patch.setattr(journal, "_directory", _fake_directory)
        patch.setattr(journal, "_publish", self.publish_record)
        patch.setattr(journal, "_record", lambda _, name, seal: self.records.get(name))

    @staticmethod
    def identity(raw, inode):
        return {
            "dev": 1,
            "ino": inode,
            "size": len(raw),
            "mtime_ns": 1,
            "ctime_ns": 1,
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
        }

    def active_policy(self, expected):
        context.require(self.enabled and expected == self.policy.policy_digest, "policy_refused")
        return self.policy

    def graph(self, policy):
        return context.Graph(
            copy.deepcopy(self.files),
            copy.deepcopy(self.identities),
            context.validate_graph(self.files, policy),
        )

    @contextmanager
    def pin(self, *_args):
        yield self.master

    @contextmanager
    def transaction(self):
        yield journal._Transaction(11)

    def syntax(self, policy, graph, candidate):
        assert context.validate_graph({**graph.files, TARGET: candidate}, policy) == ("target",)

    def probe(self, _policy, *, candidate, seconds=5):
        return candidate is self.loaded_candidate

    def reload(self):
        self.events.append("reload")
        if self.interrupted:
            raise OSError
        self.loaded_candidate = self.files[TARGET] == CANDIDATE

    def backup(self, _source, expected, path):
        raw = self.files[TARGET]
        assert context.digest(raw) == expected
        self.backups[path.name] = (
            raw,
            {
                "source_name": "backend.conf",
                "machine_sha256": "b" * 64,
                "source_identity": dict(self.identities[TARGET]),
            },
            "c" * 64,
        )

    def read_backup(self, path, _policy):
        if path.name not in self.backups:
            raise FileNotFoundError
        return self.backups[path.name]

    def publish_plan(self, path, member, data, manifest, recheck, _policy):
        assert member == "candidate.conf" and path.name not in self.plans
        recheck()
        self.plans[path.name] = (context.canonical(manifest), data)

    def read_plan(self, path, member, _policy):
        assert member == "candidate.conf"
        if path.name not in self.plans:
            raise FileNotFoundError
        return self.plans[path.name]

    def has_action(self, name):
        return any(
            value["action"] == name
            and self.records.get(key.removesuffix(".intent.json") + ".reconciliation.json", {}).get(
                "status"
            )
            != journal.UNCHANGED_FROM_PREVIEW
            for key, value in self.records.items()
            if key.endswith(".intent.json")
        )

    def publish_record(self, _fd, name, record, seal):
        assert name not in self.records
        self.events.append(name.split(".")[1])
        self.records[name] = {**record, seal: journal._digest(record)}

    @contextmanager
    def staged(self, _directory, raw, _identity):
        self.stage = raw
        yield "staged", (1, len(self.events) + 100)
        self.stage = b""

    def read_file(self, _, name, _max, _policy):
        if name == "staged":
            return self.stage, self.identity(self.stage, self.next_inode)
        assert name == "backend.conf"
        return self.files[TARGET], self.identities[TARGET]

    @property
    def next_inode(self):
        return self._staged_inode

    def replace(self, source, dest, **_kwargs):
        assert (source, dest) == ("staged", "backend.conf")
        assert self.events[-1] == "intent"
        self.events.append("replace")
        self.files[TARGET] = self.stage
        self.identities[TARGET] = self.identity(self.stage, self.next_inode)

    def call(self, op, **fields):
        self._staged_inode = len(self.events) + 100
        return action.dispatch(request(op, self.policy.policy_digest, **fields))

    def submit(self, view, *, approval_id="d" * 32):
        return self.call(
            "submit",
            approval_id=approval_id,
            **{key: view[key] for key in ("action_id", "plan_id", "plan_digest", "mode_revision")},
        )

    def reconcile_status(self, view):
        return self.call(
            "reconcile_status",
            **{key: view[key] for key in ("action_id", "plan_id", "plan_digest", "mode_revision")},
        )


@pytest.fixture
def lab(monkeypatch):
    return Lab(monkeypatch)


def test_complete_apply_status_and_separately_approved_restore(lab):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    assert view["status"] == "ready" and set(view) == action._PLAN_FIELDS
    assert view["affected_site_ids"] == ["target"] and not lab.events
    applied = lab.submit(view)
    assert applied["status"] == "verified"
    events = ["intent", "replace", "publication", "activation", "reload", "result"]
    assert lab.events == events
    assert lab.submit(view) == applied
    wrong_approval = lab.submit(view, approval_id="f" * 32)
    assert wrong_approval["status"] == "refused" and wrong_approval["reason"] == "conflict"
    assert lab.call("status", action_id=view["action_id"]) == applied
    revert = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    assert revert["status"] == "ready" and revert["action"] == "restore"
    assert revert["action_id"] != view["action_id"]
    assert revert["candidate_sha256"] == view["backup_sha256"]
    assert lab.submit(revert, approval_id="e" * 32)["status"] == "verified"
    assert lab.events == events * 2
    assert lab.files[TARGET] == ORIGINAL
    assert lab.call("status", action_id=view["action_id"]) == applied


def test_unknown_is_not_replayed_and_observation_preserves_original(lab):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    lab.interrupted = True
    result = lab.submit(view)
    assert result["status"] == "unknown"
    assert lab.submit(view) == result
    assert lab.call("observe", action_id=view["action_id"]) == result
    lab.loaded_candidate = True
    reconciled = lab.call("observe", action_id=view["action_id"])
    assert reconciled["status"] == "unknown" and reconciled["reconciliation_status"] == "verified"
    assert lab.events == [
        "intent",
        "replace",
        "publication",
        "activation",
        "reload",
        "result",
        "reconciliation",
    ]
    lab.enabled = False
    assert lab.call("status", action_id=view["action_id"]) == reconciled
    assert lab.call("plan_status", plan_id=view["plan_id"]) == view


def test_changes_in_unrelated_context_block_apply_and_restore(lab):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    name = "conf.d/sites.conf"
    original = lab.files[name]
    lab.files[name] += b"# drift\n"
    reply = lab.submit(view)
    assert reply["status"] == "refused" and reply["reason"] == "scope_changed" and not lab.events
    lab.files[name] = original
    assert lab.submit(view)["status"] == "verified"
    lab.files[name] += b"# drift\n"
    reply = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    assert reply["status"] == "refused" and reply["reason"] == "scope_changed"
    assert lab.events == ["intent", "replace", "publication", "activation", "reload", "result"]


def test_expired_missing_action_is_durably_closed_without_consuming_new_action(lab, monkeypatch):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    assert lab.reconcile_status(view)["status"] == "missing"
    assert not lab.events

    class HostClock(datetime):
        @classmethod
        def now(cls, _tz):
            return context.utc(view["expires_at"]) + timedelta(seconds=1)

    lab.enabled = False
    with monkeypatch.context() as clock:
        clock.setattr(action, "datetime", HostClock)
        mismatched = lab.reconcile_status(view | {"plan_digest": "0" * 64})
        assert mismatched["status"] == "missing" and not lab.events
        closed = lab.reconcile_status(view)
        assert closed == {
            "schema_version": 1,
            "status": "not_started",
            "action_id": view["action_id"],
            "action": "apply",
            "policy_digest": view["policy_digest"],
            "plan_id": view["plan_id"],
            "plan_digest": view["plan_digest"],
            "mode_revision": view["mode_revision"],
            "reason": "expired",
            "reconciliation_status": None,
        }

    lab.enabled = True
    # The host clock is back before expiry, but the durable closure forbids the old approval.
    assert lab.reconcile_status(view) == closed
    refused = lab.submit(view)
    assert refused["status"] == "refused" and refused["reason"] == "expired"
    assert lab.call("status", action_id=view["action_id"])["status"] == "missing"
    assert lab.events == ["not_started"]
    fresh = lab.call("prepare", plan_id="b" * 32, mode_revision=3)
    applied = lab.submit(fresh)
    assert applied["status"] == "verified"
    assert lab.reconcile_status(fresh) == applied


def test_exclusive_lock_refusal_cannot_prove_a_missing_action_never_started(lab, monkeypatch):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)

    class HostClock(datetime):
        @classmethod
        def now(cls, _tz):
            return context.utc(view["expires_at"]) + timedelta(seconds=1)

    @contextmanager
    def busy(_journal):
        raise journal.JournalError("Another action holds the journal lock")
        yield

    monkeypatch.setattr(action, "datetime", HostClock)
    monkeypatch.setattr(journal.ActionJournal, "locked", busy)
    unknown = lab.reconcile_status(view)
    assert unknown["status"] == "unknown" and unknown["reason"] == "busy"
    assert not lab.events


def test_published_candidate_with_previous_live_state_allows_disk_restore(lab, monkeypatch):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)

    def lost_after_publication(_tx, _identifier):
        raise OSError

    with monkeypatch.context() as loss:
        loss.setattr(journal._Transaction, "mark_activation", lost_after_publication)
        result = lab.submit(view)
    assert result["status"] == "unknown"
    assert lab.files[TARGET] == CANDIDATE and not lab.loaded_candidate
    assert lab.events == ["intent", "replace", "publication", "result"]
    assert lab.submit(view) == result

    observed = lab.call("observe", action_id=view["action_id"])
    assert observed == {**result, "reconciliation_status": "disk_published_live_previous"}
    assert lab.reconcile_status(view) == observed
    assert lab.call("observe", action_id=view["action_id"]) == observed
    revert = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    assert revert["status"] == "ready" and lab.files[TARGET] == CANDIDATE
    assert revert["action_id"] != view["action_id"]

    lab.loaded_candidate = True
    refused = lab.submit(revert, approval_id="e" * 32)
    assert refused["status"] == "refused" and refused["reason"] == "business_unconfirmed"
    assert lab.files[TARGET] == CANDIDATE
    lab.loaded_candidate = False
    fresh = lab.call(
        "rollback_prepare", plan_id="c" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    restored = lab.submit(fresh, approval_id="f" * 32)
    assert restored["status"] == "verified"
    assert lab.events == [
        "intent",
        "replace",
        "publication",
        "result",
        "reconciliation",
        "intent",
        "replace",
        "publication",
        "result",
    ]
    assert lab.files[TARGET] == ORIGINAL and not lab.loaded_candidate
    assert lab.call("status", action_id=view["action_id"]) == observed


def test_disk_restore_losing_its_result_can_be_independently_verified(lab, monkeypatch):
    def disconnect(*_args):
        raise OSError

    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    with monkeypatch.context() as loss:
        loss.setattr(journal._Transaction, "mark_activation", disconnect)
        assert lab.submit(view)["status"] == "unknown"
    original = lab.call("observe", action_id=view["action_id"])
    assert original["reconciliation_status"] == "disk_published_live_previous"
    revert = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    with monkeypatch.context() as loss:
        loss.setattr(journal._Transaction, "finish", disconnect)
        missing_result = lab.submit(revert, approval_id="e" * 32)
    assert missing_result["status"] == "unknown"
    assert lab.files[TARGET] == ORIGINAL and not lab.loaded_candidate

    observed_restore = lab.call("observe", action_id=revert["action_id"])
    assert observed_restore == {**missing_result, "reconciliation_status": "verified"}
    assert lab.reconcile_status(revert) == observed_restore
    assert lab.submit(revert, approval_id="e" * 32) == observed_restore
    assert lab.call("status", action_id=view["action_id"]) == original
    assert lab.events == [
        "intent",
        "replace",
        "publication",
        "result",
        "reconciliation",
        "intent",
        "replace",
        "publication",
        "reconciliation",
    ]


def test_normal_restore_losing_its_result_reconciles_without_replaying(lab, monkeypatch):
    apply = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    original = lab.submit(apply)
    assert original["status"] == "verified" and lab.loaded_candidate
    restore = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=apply["action_id"]
    )
    assert restore["status"] == "ready"

    def disconnect(*_args):
        raise OSError

    with monkeypatch.context() as loss:
        loss.setattr(journal._Transaction, "finish", disconnect)
        unknown = lab.submit(restore, approval_id="e" * 32)
    assert unknown["status"] == "unknown"
    assert lab.files[TARGET] == ORIGINAL and not lab.loaded_candidate
    assert lab.events.count("reload") == 2
    identifier = restore["action_id"]
    assert f"{identifier}.result.json" not in lab.records
    before = copy.deepcopy(lab.records)
    events = list(lab.events)

    observed = lab.call("observe", action_id=identifier)
    assert observed == {**unknown, "reconciliation_status": "verified"}
    assert lab.call("status", action_id=identifier) == observed
    assert lab.reconcile_status(restore) == observed
    assert lab.submit(restore, approval_id="e" * 32) == observed
    assert lab.call("observe", action_id=identifier) == observed
    assert lab.call("status", action_id=apply["action_id"]) == original
    assert lab.events == [*events, "reconciliation"]
    key = f"{identifier}.reconciliation.json"
    assert (
        lab.records[key]["activation_sha256"]
        == before[f"{identifier}.activation.json"]["activation_sha256"]
    )
    assert {name: value for name, value in lab.records.items() if name != key} == before


@pytest.mark.parametrize("missing", ["publication", "activation", "original_result", "live_match"])
def test_normal_restore_remains_unknown_without_independent_proof(lab, monkeypatch, missing):
    apply = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    assert lab.submit(apply)["status"] == "verified"
    restore = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=apply["action_id"]
    )
    assert restore["status"] == "ready"

    def disconnect(*_args):
        raise OSError

    with monkeypatch.context() as loss:
        method = {"publication": "publish", "activation": "mark_activation"}.get(missing, "finish")
        loss.setattr(journal._Transaction, method, disconnect)
        unknown = lab.submit(restore, approval_id="e" * 32)
    assert unknown["status"] == "unknown" and lab.files[TARGET] == ORIGINAL
    if missing == "original_result":
        lab.records.pop(f"{apply['action_id']}.result.json")
    # Isolate the missing journal witness even when both live probes match.
    lab.loaded_candidate = missing == "live_match"
    before = copy.deepcopy(lab.records)
    events = list(lab.events)
    assert lab.call("observe", action_id=restore["action_id"]) == unknown
    assert lab.records == before and lab.events == events


def test_unchanged_apply_can_close_without_replaying_and_allow_new_plan(lab, monkeypatch):
    def interrupted_rename(*_args, **_kwargs):
        raise OSError

    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    source_identity = dict(lab.identities[TARGET])
    with monkeypatch.context() as failure:
        failure.setattr(action.os, "replace", interrupted_rename)
        result = lab.submit(view)
    assert result["status"] == "unknown" and result["reconciliation_status"] is None
    assert lab.events == ["intent", "result"]
    assert lab.files[TARGET] == ORIGINAL
    blocked = lab.call("prepare", plan_id="b" * 32, mode_revision=3)
    assert blocked["status"] == "refused" and blocked["reason"] == "conflict"

    lab.identities[TARGET]["ctime_ns"] += 1
    assert lab.call("observe", action_id=view["action_id"]) == result
    lab.identities[TARGET] = source_identity
    lab.files[TARGET] = CANDIDATE
    assert lab.call("observe", action_id=view["action_id"]) == result
    lab.files[TARGET] = ORIGINAL
    lab.loaded_candidate = True
    assert lab.call("observe", action_id=view["action_id"]) == result
    lab.loaded_candidate = False
    with monkeypatch.context() as wrong_startup:
        wrong_startup.setattr(runtime, "require_started", lambda *_args, **_kwargs: "f" * 64)
        assert lab.call("observe", action_id=view["action_id"]) == result

    observed = lab.call("observe", action_id=view["action_id"])
    assert observed == {**result, "reconciliation_status": "unchanged_from_preview"}
    assert lab.call("status", action_id=view["action_id"]) == observed
    assert lab.reconcile_status(view) == observed
    assert lab.submit(view) == observed
    assert lab.events == ["intent", "result", "reconciliation"]

    fresh = lab.call("prepare", plan_id="b" * 32, mode_revision=3)
    assert fresh["action_id"] != view["action_id"]
    assert lab.submit(fresh, approval_id="e" * 32)["status"] == "verified"
    assert lab.files[TARGET] == CANDIDATE
    assert lab.events.count("replace") == lab.events.count("reload") == 1
    assert lab.call("status", action_id=view["action_id"]) == observed


@pytest.mark.parametrize("disk_only", [False, True])
def test_unchanged_restore_uses_its_planned_live_baseline(lab, monkeypatch, disk_only):
    def interrupted(*_args, **_kwargs):
        raise OSError

    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    if disk_only:
        with monkeypatch.context() as failure:
            failure.setattr(journal._Transaction, "mark_activation", interrupted)
            assert lab.submit(view)["status"] == "unknown"
        original = lab.call("observe", action_id=view["action_id"])
        assert original["reconciliation_status"] == "disk_published_live_previous"
    else:
        original = lab.submit(view)
        assert original["status"] == "verified"
    assert lab.loaded_candidate is not disk_only
    view_restore = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    with monkeypatch.context() as failure:
        failure.setattr(action.os, "replace", interrupted)
        unknown_restore = lab.submit(view_restore, approval_id="e" * 32)
    assert unknown_restore["status"] == "unknown"

    lab.loaded_candidate = disk_only
    assert lab.call("observe", action_id=view_restore["action_id"]) == unknown_restore
    lab.loaded_candidate = not disk_only
    observed = lab.call("observe", action_id=view_restore["action_id"])
    assert observed == {**unknown_restore, "reconciliation_status": "unchanged_from_preview"}
    assert lab.submit(view_restore, approval_id="e" * 32) == observed
    assert lab.call("status", action_id=view["action_id"]) == original
    assert lab.files[TARGET] == CANDIDATE
    unrelated = lab.call("prepare", plan_id="d" * 32, mode_revision=3)
    assert unrelated["status"] == "refused" and unrelated["reason"] == "conflict"

    fresh = lab.call(
        "rollback_prepare", plan_id="c" * 32, mode_revision=3, original_action_id=view["action_id"]
    )
    assert lab.submit(fresh, approval_id="f" * 32)["status"] == "verified"
    assert lab.files[TARGET] == ORIGINAL
    assert lab.events.count("replace") == 2
    assert lab.events.count("reload") == (0 if disk_only else 2)
    assert lab.call("status", action_id=view["action_id"]) == original


@pytest.mark.parametrize("process_stopped", [False, True])
def test_rename_before_publication_recovers_only_the_original_staged_inode(
    lab, monkeypatch, process_stopped
):
    view = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
    identifier = view["action_id"]

    def stop_after_rename(*_args):
        if process_stopped:
            raise SystemExit(75)
        raise OSError

    with monkeypatch.context() as loss:
        loss.setattr(journal._Transaction, "publish", stop_after_rename)
        if process_stopped:
            with pytest.raises(SystemExit):
                lab.submit(view)
        else:
            assert lab.submit(view)["status"] == "unknown"
    assert lab.files[TARGET] == CANDIDATE and not lab.loaded_candidate
    result_name = f"{identifier}.result.json"
    before = lab.records.get(result_name)
    original_inode = lab.identities[TARGET]
    lab.identities[TARGET] = {**original_inode, "ino": original_inode["ino"] + 1}
    assert lab.call("observe", action_id=identifier)["reconciliation_status"] is None
    lab.identities[TARGET] = {**original_inode, "ctime_ns": original_inode["ctime_ns"] + 1}
    recovered = lab.call("observe", action_id=identifier)
    assert recovered["status"] == "unknown"
    assert recovered["reconciliation_status"] == "disk_published_live_previous"
    assert lab.records.get(result_name) == before
    assert lab.events.count("observed_publication") == 1 and "reload" not in lab.events
    assert lab.submit(view) == recovered
    restore = lab.call(
        "rollback_prepare", plan_id="b" * 32, mode_revision=3, original_action_id=identifier
    )
    assert lab.submit(restore)["status"] == "verified"
    assert lab.files[TARGET] == ORIGINAL and "reload" not in lab.events


def test_restore_capacity_is_reserved_when_apply_budget_is_full(monkeypatch):
    @contextmanager
    def private_directory(path, *_args, **_kwargs):
        yield path.name

    @contextmanager
    def records(name):
        assert name == "plans"
        yield (SimpleNamespace(name=f"existing-{index}") for index in range(24))

    monkeypatch.setattr(snapshot, "_directory", private_directory)
    monkeypatch.setattr(action.os, "scandir", records)
    with pytest.raises(context.Refused, match="busy"):
        action._plan_capacity("a" * 32, restore=False)
    action._plan_capacity("a" * 32, restore=True)


def test_apply_cannot_write_without_same_startup_witness(lab, monkeypatch):
    with monkeypatch.context() as missing:

        def refuse(*_args, **_kwargs):
            raise context.Refused("scope_changed")

        missing.setattr(runtime, "require_started", refuse)
        refused = lab.call("prepare", plan_id="a" * 32, mode_revision=3)
        assert refused["status"] == "refused" and not lab.events and not lab.plans
    view = lab.call("prepare", plan_id="b" * 32, mode_revision=3)
    assert view["status"] == "ready" and "startup_sha256" not in view
    monkeypatch.setattr(runtime, "require_started", lambda *_args, **_kwargs: "f" * 64)
    result = lab.submit(view)
    assert result["status"] == "refused" and result["reason"] == "scope_changed"
    assert lab.files[TARGET] == ORIGINAL and not lab.events


def test_native_post_pid_file_candidate_must_be_pinned(lab, monkeypatch):
    inspected = []
    pin_events = []

    def read_pid(path, size):
        assert (path, size) == (context.PID_PATH, 32)
        return b"42\n", {}

    def inspect(policy, graph, pid):
        assert policy == lab.policy and graph == lab.graph(lab.policy)
        inspected.append(pid)
        return context.ProcessIdentity(birth_tick=31, sha256="d" * 64)

    def open_pidfd(pid):
        pin_events.append(("open", pid))
        return 7

    monkeypatch.setattr(context, "trusted_read", read_pid)
    monkeypatch.setattr(context, "inspect_master", inspect)
    monkeypatch.setattr(
        runtime,
        "os",
        SimpleNamespace(pidfd_open=open_pidfd, close=lambda fd: pin_events.append(("close", fd))),
    )
    monkeypatch.setattr(
        runtime,
        "signal",
        SimpleNamespace(
            pidfd_send_signal=lambda fd, value: pin_events.append(("signal", fd, value))
        ),
    )
    source = runtime.NativeEvidence(lab.policy)
    identity = source.master(0, source.graph())
    assert identity.pid == 42 and identity.born_at_ticks == 31
    assert inspected == [42, 42]
    assert pin_events == [("open", 42), ("signal", 7, 0), ("close", 7)]
