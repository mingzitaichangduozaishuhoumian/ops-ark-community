"""Synthetic inode/FD evidence; no deployment credentials, remote calls or models."""

import hashlib
import json
import stat
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.readonly import disk_reclaim as helper
from deploy.readonly import install_disk_reclaim as installer
from opsark.ai import explanation_input
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.collector import commands_for, disk_reclaim_command
from opsark.config import HostConfig, Settings, load_hosts
from opsark.diagnostics import diagnose
from opsark.disk_reclaim import parse_disk_reclaim, safe_disk_check
from opsark.models import CheckResult, Collection, HostPublic


def scope():
    return helper.canonical(
        {
            "schema_version": 1,
            "directories": [
                {"path": "/srv/registered-logs", "category": "log"},
                {"path": "/srv/registered-data", "category": "business"},
            ],
            "process_ids": [101],
            "max_depth": 1,
        }
    )


def meta(inode, *, mode=stat.S_IFREG | 0o600, size=1024, blocks=8, links=1, device=1):
    return SimpleNamespace(
        st_dev=device,
        st_ino=inode,
        st_mode=mode,
        st_nlink=links,
        st_size=size,
        st_blocks=blocks,
        st_mtime_ns=1,
        st_ctime_ns=1,
        st_uid=0,
    )


class Metadata:
    def __init__(self):
        sparse = meta(11, size=2**30, links=2)
        self.stats = {
            "/": meta(1, mode=stat.S_IFDIR | 0o755),
            "/srv/registered-logs": meta(2, mode=stat.S_IFDIR | 0o755),
            "/srv/registered-data": meta(3, mode=stat.S_IFDIR | 0o755),
            "/proc/101/fd": meta(4, mode=stat.S_IFDIR | 0o500),
            "/srv/registered-logs/a.log": sparse,
            "/srv/registered-logs/b.log": sparse,
            "/srv/registered-logs/closed.log": meta(12, blocks=16),
            "/srv/registered-logs/external-link.log": meta(13, links=2, blocks=1),
            "/srv/registered-data/data.db": meta(14, size=2**34, blocks=16),
        }
        self.fds = {
            "3": ("/srv/registered-logs/a.log", sparse),
            "4": ("/srv/registered-logs/b.log", sparse),
            "5": ("/srv/registered-logs/deleted.log (deleted)", meta(15, links=0)),
            "6": ("/srv/registered-data/data.db", self.stats["/srv/registered-data/data.db"]),
            "7": ("pipe:[123]", meta(20, mode=stat.S_IFIFO | 0o600)),
        }

    def directory(self, path):
        assert path in self.stats
        return path

    def child(self, parent, name):
        return parent + "/" + name

    def metadata(self, handle, name=None):
        return self.stats[handle if name is None else handle + "/" + name]

    def entries(self, handle):
        if handle == "/proc/101/fd":
            return sorted(self.fds)
        return sorted(
            path[len(handle) + 1 :]
            for path in self.stats
            if path.startswith(handle + "/") and "/" not in path[len(handle) + 1 :]
        )

    def fd_metadata(self, handle, name):
        assert handle == "/proc/101/fd"
        return self.fds[name]


def check(value=None):
    return CheckResult(
        name="disk_reclaim",
        stdout=helper.canonical(
            helper.project(scope(), Metadata()) if value is None else value
        ).decode(),
    )


def host():
    return HostPublic(
        id="fixture",
        name="Fixture",
        address="192.0.2.1",
        disk_reclaim_scope_digest=helper.digest(scope()),
    )


def collection(evidence):
    return Collection(
        host_id="fixture",
        source="replay",
        started_at=datetime.now(UTC),
        checks=[
            CheckResult(name="os_release", stdout='ID=ubuntu\nVERSION_ID="24.04"\n'),
            CheckResult(
                name="disk_bytes",
                stdout=(
                    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    "/dev/vda 10000 9900 100 99% /\n"
                ),
            ),
            CheckResult(
                name="disk_inodes",
                stdout=(
                    "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
                    "/dev/vda 10000 9900 100 99% /\n"
                ),
            ),
            evidence,
        ],
    )


def signed(value):
    value = deepcopy(value)
    value.pop("snapshot_digest", None)
    value["snapshot_digest"] = helper.digest(helper.canonical(value))
    return value


def test_sparse_hardlinks_fd_dedup_business_and_deleted_have_conditional_bounds():
    value = helper.project(scope(), Metadata())
    result = parse_disk_reclaim(check(value), helper.digest(scope()))
    assert len(result.objects) == 5
    assert result.conditional_log_upper_bytes == 16384
    assert result.conditional_lower_bytes == 0
    assert result.immediate_reclaimable_bytes is None
    sparse = next(row for row in result.objects if row.logical_bytes == 2**30)
    assert sparse.allocated_bytes == 4096
    assert sparse.scoped_link_count == sparse.link_count == 2
    assert sparse.holder_refs == ["process-1"]
    assert sparse.conditional_upper_bytes == 4096
    deleted = next(row for row in result.objects if row.state == "deleted_held")
    assert deleted.release_condition == "all_holders_close"
    external = next(
        row for row in result.objects if row.link_count == 2 and row.scoped_link_count == 1
    )
    assert external.release_condition == "unscoped_links_unknown"
    assert external.conditional_upper_bytes == 0
    business = next(row for row in result.objects if row.category == "business")
    assert business.allocated_bytes == 8192 and business.conditional_upper_bytes == 0
    assert business.release_condition == "business_excluded"
    text = json.dumps(value)
    for path in ("/srv", "/proc", "a.log", "data.db", "deleted.log"):
        assert path not in text
    assert value["snapshot_atomic"] is False and value["actions_enabled"] is False


def test_hardlinks_across_registered_log_directories_are_deduplicated():
    value = json.loads(scope())
    value["directories"].append({"path": "/srv/second-logs", "category": "log"})
    raw = helper.canonical(value)
    fs = Metadata()
    fs.stats["/srv/second-logs"] = meta(100, mode=stat.S_IFDIR | 0o755)
    fs.stats["/srv/second-logs/external-now-scoped.log"] = meta(13, links=2, blocks=1)
    result = helper.project(raw, fs)
    parsed = parse_disk_reclaim(check(result), helper.digest(raw))
    assert len(parsed.objects) == 5
    assert parsed.conditional_log_upper_bytes == 16384 + 512
    linked = next(row for row in parsed.objects if len(row.directory_refs) == 2)
    assert linked.directory_refs == ["directory-1", "directory-3"]
    assert linked.scoped_link_count == linked.link_count == 2
    assert linked.allocated_bytes == linked.conditional_upper_bytes == 512


@pytest.mark.parametrize(
    "change,reason",
    [
        (
            lambda fs: fs.fds.update({"3": ("/srv/outside/a.log", meta(11, links=2))}),
            "scope_exceeded",
        ),
        (
            lambda fs: fs.fds.update(
                {"3": ("/srv/registered-logs/../outside/a.log", meta(11, links=2))}
            ),
            "scope_exceeded",
        ),
        (
            lambda fs: fs.fds.update(
                {"5": ("/srv/registered-logs/deleted.log", meta(15, links=0))}
            ),
            "metadata_changed",
        ),
        (
            lambda fs: fs.stats.update(
                {"/srv/registered-logs/a.log": meta(11, mode=stat.S_IFLNK | 0o777)}
            ),
            "metadata_unsupported",
        ),
        (
            lambda fs: fs.stats.update({"/srv/registered-logs/token.txt": meta(22)}),
            "metadata_sensitive",
        ),
        (
            lambda fs: fs.stats.update({"/srv/registered-logs/new.log": meta(22, device=2)}),
            "scope_exceeded",
        ),
        (
            lambda fs: fs.stats.update(
                {"/srv/registered-logs": meta(2, mode=stat.S_IFDIR | 0o755, device=2)}
            ),
            "scope_exceeded",
        ),
        (
            lambda fs: fs.fds.update({"3": ("/srv/registered-logs/a.log", meta(999))}),
            "metadata_changed",
        ),
        (
            lambda fs: fs.fds.update({"3": ("/srv/registered-logs/token.txt", meta(11, links=2))}),
            "metadata_sensitive",
        ),
        (
            lambda fs: fs.stats.update({"/srv/registered-data/cross.log": meta(11, links=2)}),
            "scope_exceeded",
        ),
    ],
)
def test_unknown_sensitive_cross_mount_symlink_and_scope_escape_reject_entire_snapshot(
    change, reason
):
    fs = Metadata()
    change(fs)
    with pytest.raises(helper.Refused, match=reason):
        helper.project(scope(), fs)


def test_missing_permissions_timeout_races_and_limits_never_produce_partial_estimates():
    fs = Metadata()
    fs.entries = lambda _handle: (_ for _ in ()).throw(PermissionError())
    with pytest.raises(PermissionError):
        helper.project(scope(), fs)
    with pytest.raises(helper.Refused, match="collection_timeout"):
        helper.project(scope(), Metadata(), clock=iter([0, 10]).__next__)
    fs = Metadata()
    original = fs.fd_metadata
    calls = 0

    def changed(handle, name):
        nonlocal calls
        calls += 1
        path, info = original(handle, name)
        return (path, meta(99)) if calls > 5 and name == "3" else (path, info)

    fs.fd_metadata = changed
    with pytest.raises(helper.Refused, match="metadata_changed"):
        helper.project(scope(), fs)
    fs = Metadata()
    for i in range(40):
        fs.stats[f"/srv/registered-logs/extra-{i}.log"] = meta(100 + i)
    with pytest.raises(helper.Refused, match="collection_limit"):
        helper.project(scope(), fs)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": "unclassified"}),
        lambda value: value.update({"actions_enabled": True}),
        lambda value: value.update({"immediate_reclaimable_bytes": 100}),
        lambda value: value.update({"conditional_lower_bytes": False}),
        lambda value: value.update({"actions_enabled": 0}),
        lambda value: value.update({"conditional_log_upper_bytes": 999}),
        lambda value: value["objects"][0].update({"raw_path": "/srv/private"}),
        lambda value: value["objects"][0].update({"allocated_bytes": True}),
        lambda value: value["objects"][0].update({"holder_refs": ["unclassified"]}),
        lambda value: value["objects"].append(value["objects"][0]),
        lambda value: value["objects"][0].update({"state": "deleted_held"}),
        lambda value: value["objects"][0].update({"conditional_upper_bytes": 3000}),
    ],
)
def test_controller_rejects_unknown_and_inconsistent_signed_payloads(mutation):
    value = helper.project(scope(), Metadata())
    mutation(value)
    with pytest.raises(ValueError, match="Disk metadata rejected"):
        parse_disk_reclaim(check(signed(value)), helper.digest(scope()))


@pytest.mark.parametrize(
    "update",
    [
        {"truncated": True},
        {"stderr": "raw private path"},
        {"status": "timeout"},
        {"exit_code": 1},
        {"stdout": '{"schema":1,"schema":2}'},
    ],
)
def test_controller_clears_partial_replies_and_diagnostics_block_whole_ai_request(update):
    bad = check().model_copy(update=update)
    clean, refused = safe_disk_check(bad, helper.digest(scope()))
    assert refused and not clean.stdout and "raw private path" not in clean.stderr
    report = diagnose("disk", host(), collection(bad))
    assert report.ai_egress_block_reason == "unclassified_payload"
    assert all("raw private path" not in item.output for item in report.evidence)
    assert any("不提供回收容量估算" in item for item in report.missing)
    with pytest.raises(ValueError):
        explanation_input(report)


def test_report_explains_conditions_and_ai_only_sees_categories():
    report = diagnose("disk", host(), collection(check()))
    assert report.status == "needs_attention"
    assert report.ai_egress_block_reason is None
    assert any("0 至 16384 字节" in item.text for item in report.facts)
    assert any("已删除仍持有" in item.text for item in report.facts)
    assert any("业务数据排除清理" in item.text for item in report.facts)
    assert any("共享块" in item for item in report.missing)
    summary = explanation_input(report)
    encoded = json.dumps(summary)
    assert "disk_object_metadata" in encoded and "disk_conditional_reclaim_bound" in encoded
    for item in ("/srv", "16384", "directory-1", "process-1", helper.digest(scope())):
        assert item not in encoded
    assert summary["actions_executable"] is False


@pytest.mark.parametrize(
    "update",
    [
        {"extra": True},
        {"process_ids": []},
        {"process_ids": [True]},
        {"process_ids": [101, 101]},
        {"max_depth": 99},
        {"directories": [{"path": "/srv", "category": "log"}]},
        {"directories": [{"path": "/etc/nginx", "category": "log"}]},
        {"directories": [{"path": "/srv/../other", "category": "log"}]},
        {"directories": [{"path": "/srv/data", "category": "unknown"}]},
        {
            "directories": [
                {"path": "/srv/data", "category": "log"},
                {"path": "/srv/data/sub", "category": "business"},
            ]
        },
    ],
)
def test_only_closed_exact_registration_is_accepted(update):
    value = json.loads(scope())
    value.update(update)
    with pytest.raises(helper.Refused):
        helper.checked_scope(helper.canonical(value))


def test_scope_binding_collection_policy_and_historical_scope_stability():
    public = host()
    target = HostConfig(public=public, key_file=Path("unused"), known_hosts_file=Path("unused"))
    assert disk_reclaim_command(target) == "timeout -k 1s 5s /usr/local/libexec/opsark-disk-reclaim"
    assert "disk_reclaim" in commands_for(target, "disk")
    assert "disk_directories" not in commands_for(target, "disk")
    before = public.model_copy(update={"disk_reclaim_scope_digest": None})
    old_values = before.model_dump(
        mode="json", exclude={"name", "web_profile_digest", "disk_reclaim_scope_digest"}
    )
    historical = hashlib.sha256(
        json.dumps(old_values, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert scope_for(before) == historical
    assert scope_for(public) == historical
    assert diagnostic_scope_for(before) == historical
    assert diagnostic_scope_for(public) != historical
    with pytest.raises(ValueError):
        disk_reclaim_command(replace(target, public=before))
    with pytest.raises(ValueError):
        parse_disk_reclaim(check(), "0" * 64)


def test_inventory_policy_export_uses_digest_and_does_not_read_private_reference(
    tmp_path, monkeypatch
):
    from test_compose_discovery_api import TOKEN, _inventory

    from deploy.readonly.export_policy import export_policy
    from deploy.readonly.guard import parse_policy

    inventory = _inventory(tmp_path, "demo")
    inventory.write_text(
        inventory.read_text() + 'disk_reclaim_scope_digest = "' + helper.digest(scope()) + '"\n'
    )
    original = Path.open

    def checked(path, *args, **kwargs):
        assert path != tmp_path / "key"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked)
    settings = Settings(data_dir=tmp_path, token=TOKEN, inventory_path=inventory)
    registered = load_hosts(settings)["fixture"]
    assert registered.public.disk_reclaim_scope_digest == helper.digest(scope())
    output = tmp_path / "exported-policy.json"
    export_policy(inventory, "fixture", output)
    policy = parse_policy(output.read_bytes())
    assert policy[installer.COMMAND] == [
        "timeout",
        "-k",
        "1s",
        "5s",
        "/usr/local/libexec/opsark-disk-reclaim",
    ]
    assert not any("du -xsk" in command for command in policy)
    assert not any("--locate-ref" in command for command in policy)


def test_installer_refuses_digest_policy_and_drift_before_writes(tmp_path, monkeypatch):
    # Installation is simulated only. No /etc, SSH, root privilege or deployment state is used.
    raw = scope()
    source = Path(installer.__file__).parent / "disk_reclaim.py"
    target, configured, marker = (tmp_path / name for name in ("helper", "scope", "marker"))
    monkeypatch.setattr(installer, "TARGET", target)
    monkeypatch.setattr(installer, "SCOPE", configured)
    monkeypatch.setattr(installer, "MARKER", marker)
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        installer.sys,
        "argv",
        ["install", "--scope", str(tmp_path / "input"), "--expected-sha256", helper.digest(raw)],
    )
    policy = {"commands": {installer.COMMAND: ["timeout", "-k", "1s", "5s", str(target)]}}

    def read(path, _limit):
        if path == tmp_path / "input":
            return raw
        if path == source:
            return source.read_bytes()
        if path == installer.POLICY:
            return json.dumps(policy).encode()
        return path.read_bytes()

    monkeypatch.setattr(installer, "read_root", read)
    writes = []

    def write(path, data, _mode):
        writes.append(path)
        path.write_bytes(data)

    monkeypatch.setattr(installer, "write_root", write)
    installer.main()
    assert writes == [marker, target, configured, marker]
    assert json.loads(marker.read_bytes())["scope_sha256"] == helper.digest(raw)
    writes.clear()
    target.write_bytes(b"unrelated drift")
    with pytest.raises(ValueError, match="drifted"):
        installer.main()
    assert not writes
    target.unlink()
    configured.unlink()
    policy["commands"].clear()
    with pytest.raises(ValueError, match="Exact helper"):
        installer.main()
    assert not writes
    monkeypatch.setattr(
        installer.sys,
        "argv",
        ["install", "--scope", str(tmp_path / "input"), "--expected-sha256", "0" * 64],
    )
    with pytest.raises(ValueError, match="Scope digest"):
        installer.main()
    assert not writes


def test_linux_adapter_opens_only_no_follow_directories_and_stats_fd_metadata(monkeypatch):
    # Exercise the real adapter syscall contract with synthetic descriptors on Windows too.
    opened, closed, stats, links = [], [], [], []
    for name, value in (("O_DIRECTORY", 0x10000), ("O_NOFOLLOW", 0x20000), ("O_CLOEXEC", 0x40000)):
        monkeypatch.setattr(helper.os, name, value, raising=False)

    def opened_directory(path, flags, **kwargs):
        assert flags & helper.os.O_DIRECTORY and not flags & helper.os.O_WRONLY
        if path != "/":
            assert flags & helper.os.O_NOFOLLOW
        opened.append((path, flags, kwargs))
        return 100 + len(opened)

    def metadata(path, **kwargs):
        stats.append((path, kwargs))
        return meta(1)

    def readlink(path, **kwargs):
        links.append((path, kwargs))
        return "/srv/registered-logs/a.log"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Data bytes must never be read")

    monkeypatch.setattr(helper.os, "open", opened_directory)
    monkeypatch.setattr(helper.os, "close", closed.append)
    monkeypatch.setattr(helper.os, "stat", metadata)
    monkeypatch.setattr(helper.os, "fstat", lambda _: meta(1))
    monkeypatch.setattr(helper.os, "readlink", readlink)
    monkeypatch.setattr(helper.os, "read", forbidden)
    fs = helper.Filesystem()
    handle = fs.directory("/srv/registered-logs")
    assert [row[0] for row in opened] == ["/", "srv", "registered-logs"]
    fs.metadata(handle, "a.log")
    fs.fd_metadata(handle, "3")
    assert stats == [
        ("a.log", {"dir_fd": handle, "follow_symlinks": False}),
        ("3", {"dir_fd": handle, "follow_symlinks": True}),
    ]
    assert links == [("3", {"dir_fd": handle}), ("3", {"dir_fd": handle})]
    fs.close()
    assert closed == [103, 102, 101]


@pytest.mark.parametrize("reason", ["collection_timeout", "scope_exceeded", "/srv/raw-refused"])
def test_helper_failures_only_emit_closed_reason_without_partial_metadata(
    reason, monkeypatch, capsys
):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0, raising=False)
    for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
        monkeypatch.setattr(helper.os, name, 1, raising=False)
    monkeypatch.setattr(
        helper,
        "signal",
        SimpleNamespace(
            SIGALRM=14, ITIMER_REAL=0, signal=lambda *_: None, setitimer=lambda *_: None
        ),
    )
    monkeypatch.setattr(helper, "load_scope", scope)

    def rejected(_):
        raise helper.Refused(reason)

    monkeypatch.setattr(helper, "project", rejected)
    assert helper.main([]) == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert set(result) == {"schema", "reason", "actions_enabled"}
    assert result["reason"] == (reason if reason in helper.REASONS else "metadata_unavailable")
    assert result["actions_enabled"] is False
    assert "/srv" not in captured.out and not captured.err


def test_operator_instructions_are_in_the_deployment_source_bundle_allowlist():
    from tools.release_bundle import _allowed, _check_content

    assert _allowed("docs/DISK_RECLAIM_EVIDENCE.md")
    assert _allowed("deploy/readonly/disk_reclaim.py")
    assert _allowed("deploy/readonly/install_disk_reclaim.py")
    _check_content("deploy/readonly/disk_reclaim.py", Path(helper.__file__).read_bytes())


def test_local_admin_locator_recollects_and_maps_hardlinks_and_fds_only_locally():
    baseline = helper.project(scope(), Metadata())
    obj = next(row for row in baseline["objects"] if row["logical_bytes"] == 2**30)
    located = helper.locate(
        scope(), obj["object_ref"], helper.digest(scope()), baseline["snapshot_digest"], Metadata()
    )
    assert located["schema"] == "opsark-disk-object-location-local/v1"
    assert located["administrator_local_only"] is True and located["actions_enabled"] is False
    assert {item["path"] for item in located["locations"] if item["kind"] == "linked_path"} == {
        "/srv/registered-logs/a.log",
        "/srv/registered-logs/b.log",
    }
    assert {
        (item["pid"], item["fd"])
        for item in located["locations"]
        if item["kind"] == "open_descriptor"
    } == {(101, 3), (101, 4)}
    assert "locations" not in json.dumps(baseline)
    safe, rejected = safe_disk_check(check(located), helper.digest(scope()))
    assert rejected and not safe.stdout and "/srv" not in safe.stderr
    report = diagnose("disk", host(), collection(check(located)))
    assert report.ai_egress_block_reason == "unclassified_payload"
    assert all("/srv" not in item.output for item in report.evidence)


def test_local_locator_rejects_scope_change_disappearance_forged_ref_and_stale_inode():
    baseline = helper.project(scope(), Metadata())
    ref = baseline["objects"][0]["object_ref"]
    changed = json.loads(scope())
    changed["max_depth"] = 2
    with pytest.raises(helper.Refused, match="scope_invalid"):
        helper.locate(
            helper.canonical(changed),
            ref,
            helper.digest(scope()),
            baseline["snapshot_digest"],
            Metadata(),
        )
    with pytest.raises(helper.Refused, match="object_unavailable"):
        helper.locate(
            scope(), "0" * 64, helper.digest(scope()), baseline["snapshot_digest"], Metadata()
        )
    with pytest.raises(helper.Refused, match="scope_invalid"):
        helper.locate(
            scope(), ref + ";touch", helper.digest(scope()), baseline["snapshot_digest"], Metadata()
        )
    fs = Metadata()
    del fs.stats["/srv/registered-logs/closed.log"]
    with pytest.raises(helper.Refused, match="metadata_changed"):
        helper.locate(scope(), ref, helper.digest(scope()), baseline["snapshot_digest"], fs)
    fs = Metadata()
    fs.stats["/srv/registered-logs/a.log"].st_ctime_ns = 2
    with pytest.raises(helper.Refused, match="metadata_changed"):
        helper.locate(scope(), ref, helper.digest(scope()), baseline["snapshot_digest"], fs)
    fs = Metadata()
    fs.stats["/srv/registered-logs/token.txt"] = meta(100)
    with pytest.raises(helper.Refused, match="metadata_sensitive"):
        helper.locate(scope(), ref, helper.digest(scope()), baseline["snapshot_digest"], fs)


def test_local_locator_cli_requires_root_and_exact_checked_arguments(monkeypatch, capsys):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0, raising=False)
    for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
        monkeypatch.setattr(helper.os, name, 1, raising=False)
    monkeypatch.setattr(
        helper,
        "signal",
        SimpleNamespace(
            SIGALRM=14, ITIMER_REAL=0, signal=lambda *_: None, setitimer=lambda *_: None
        ),
    )
    monkeypatch.setattr(helper, "load_scope", scope)
    calls = []

    def locate(raw, ref, scope_sha, snapshot):
        calls.append((raw, ref, scope_sha, snapshot))
        return {"local": True}

    monkeypatch.setattr(helper, "locate", locate)
    args = [
        "--locate-ref",
        "a" * 64,
        "--expected-scope-sha256",
        helper.digest(scope()),
        "--expected-snapshot-sha256",
        "b" * 64,
    ]
    assert helper.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {"local": True}
    assert calls == [(scope(), "a" * 64, helper.digest(scope()), "b" * 64)]
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    assert helper.main(args) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "path_untrusted"
    assert len(calls) == 1
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    for malformed in (args[:-1], args + ["--extra"], ["--unknown", *args[1:]]):
        assert helper.main(malformed) == 1
        assert json.loads(capsys.readouterr().out)["reason"] == "scope_invalid"
    assert len(calls) == 1
