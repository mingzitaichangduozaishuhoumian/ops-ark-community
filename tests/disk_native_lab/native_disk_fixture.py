#!/usr/bin/env python3
"""Fake data only. No SSH, installation, model, package, mount or service action."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
COMMIT = "01176af92147ec511081aa21f54810485abbf823"
SOURCE = Path("/opt/opsark-reviewed")
ROOT = Path("/var/tmp/oa-native-fixture-20261107")  # noqa: S108 -- exclusive owned fixture root.
RESULT = Path("/fixture-results/result.json")
MANIFEST_SHA256 = "4300767cc42aafaf706a3faa842b2f6e494ac2794a75b0d8a540509670f05db9"
MARKER = b"opsark-fake-files-only/native-fixture-20261107/v1\n"
MIB = 1024 * 1024
SIZES = {
    "sparse": 64 * MIB,
    "ordinary": 2 * MIB,
    "deleted_log": 4 * MIB,
    "mapped": 3 * MIB,
    "growth_log": MIB,
    "business": 5 * MIB,
    "deleted_business": 6 * MIB,
}
NAMES = {
    "sparse": "logs-a/sparse.log",
    "sparse_alias": "logs-b/alias.log",
    "ordinary": "logs-a/ordinary.log",
    "deleted_log": "logs-a/deleted.log",
    "mapped": "logs-a/mapped.log",
    "growth_log": "logs-b/growth.log",
    "business": "business/growth.dat",
    "deleted_business": "business/deleted.dat",
}
FAILURES = {
    "check_failed",
    "source_rejected",
    "profile_rejected",
    "root_exists",
    "holder_failed",
    "output_rejected",
    "native_failed",
    "self_test_failed",
}


class FixtureRejected(Exception):
    pass


def require(value, reason="check_failed"):
    if not value:
        raise FixtureRejected(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "urllib.Request"}:
        raise FixtureRejected("profile_rejected")


def verify_source(source):
    raw = (Path(__file__).parent / "source-manifest.json").read_bytes()
    require(sha(raw) == MANIFEST_SHA256, "source_rejected")
    manifest = json.loads(raw)
    require(manifest["commit"] == COMMIT, "source_rejected")
    require(
        source.is_absolute()
        and source.resolve() == source
        and all(not p.is_symlink() for p in [source, *source.parents])
        and source.is_dir(),
        "source_rejected",
    )
    for relative, expected in manifest["files"].items():
        target = source.joinpath(*relative.split("/"))
        require(target.is_relative_to(source), "source_rejected")
        parent = source
        for part in relative.split("/")[:-1]:
            parent = parent / part
            require(not parent.is_symlink(), "source_rejected")
        require(not target.is_symlink() and target.is_file(), "source_rejected")
        require(sha(target.read_bytes()) == expected, "source_rejected")
    return {
        "commit": COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "helper_sha256": manifest["files"]["deploy/readonly/disk_reclaim.py"],
        "all_manifest_bytes_verified": True,
    }


def load_product(source, state):
    sys.path[:0] = [str(source / "src"), str(source)]
    helper = importlib.import_module("deploy.readonly.disk_reclaim")
    config = importlib.import_module("opsark.config")
    settings = config.Settings(data_dir=state / "app", token="public-fixture-" + "0" * 32)
    original = config.load_settings
    config.load_settings = lambda: settings
    try:
        main = importlib.import_module("opsark.main")
    finally:
        config.load_settings = original
    ai = importlib.import_module("opsark.ai")
    calls = []

    def forbidden_model(*_args, **_kwargs):
        calls.append(True)
        raise FixtureRejected("profile_rejected")

    ai.request_document = forbidden_model
    return SimpleNamespace(
        helper=helper,
        main=main,
        ai=ai,
        model_calls=calls,
        models=importlib.import_module("opsark.models"),
        disk=importlib.import_module("opsark.disk_reclaim"),
        diagnostics=importlib.import_module("opsark.diagnostics"),
        baselines=importlib.import_module("opsark.baselines"),
        storage=importlib.import_module("opsark.storage"),
    )


def make_scope(helper, pid, depth=0):
    return helper.canonical(
        {
            "schema_version": 1,
            "directories": [
                {"path": (ROOT / "logs-a").as_posix(), "category": "log"},
                {"path": (ROOT / "business").as_posix(), "category": "business"},
                {"path": (ROOT / "logs-b").as_posix(), "category": "log"},
            ],
            "process_ids": [pid],
            "max_depth": depth,
        }
    )


def statvfs_sample(stage):
    v = os.statvfs(ROOT)
    return {
        "stage": stage,
        "block_unit_bytes": v.f_frsize,
        "blocks": v.f_blocks,
        "free_blocks": v.f_bfree,
        "available_blocks": v.f_bavail,
        "inodes": v.f_files,
        "free_inodes": v.f_ffree,
    }


def fake_vfs(stage):
    return {
        "stage": stage,
        "block_unit_bytes": 4096,
        "blocks": 100000,
        "free_blocks": 1000,
        "available_blocks": 500,
        "inodes": 100000,
        "free_inodes": 1000,
    }


def report_for(p, raw, projection, v):
    m = p.models
    host = m.HostPublic(
        id="fixture",
        name="Fixture",
        address="192.0.2.1",
        source="replay",
        disk_reclaim_scope_digest=p.helper.digest(raw),
    )
    unit = v["block_unit_bytes"]
    total = v["blocks"] * unit // 1024
    used = (v["blocks"] - v["free_blocks"]) * unit // 1024
    available = v["available_blocks"] * unit // 1024
    iused = v["inodes"] - v["free_inodes"]

    def pct(used, available):
        return (100 * used + used + available - 1) // max(1, used + available)

    collection = m.Collection(
        host_id="fixture",
        source="replay",
        started_at=datetime.now(UTC),
        checks=[
            m.CheckResult(name="os_release", stdout='ID=ubuntu\nVERSION_ID="24.04"\n'),
            m.CheckResult(
                name="disk_bytes",
                stdout=(
                    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    f"fixture-root {total} {used} {available} {pct(used, available)}% /\n"
                ),
            ),
            m.CheckResult(
                name="disk_inodes",
                stdout=(
                    "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
                    f"fixture-root {v['inodes']} {iused} "
                    f"{v['free_inodes']} {pct(iused, v['free_inodes'])}% /\n"
                ),
            ),
            m.CheckResult(name="disk_reclaim", stdout=p.helper.canonical(projection).decode()),
        ],
    )
    report = p.diagnostics.diagnose("disk", host, collection)
    report.scope_hash = p.baselines.scope_for(host)
    return report


def closed_projection(p, raw, value):
    check = p.models.CheckResult(name="disk_reclaim", stdout=p.helper.canonical(value).decode())
    parsed = p.disk.parse_disk_reclaim(check, p.helper.digest(raw))
    text = p.helper.canonical(value).decode()
    require(str(ROOT) not in text and "/proc/" not in text)
    require(all(n.split("/")[-1] not in text for n in NAMES.values()))
    require(parsed.actions_enabled is False and parsed.physical_reclaim_verified is False)
    require(parsed.immediate_reclaimable_bytes is None and parsed.conditional_lower_bytes == 0)
    return parsed


def product_contract(p, state, raw, first, second, drift_raw, drift, vfs):
    before = report_for(p, raw, first, vfs)
    after = report_for(p, raw, second, vfs)
    require(before.ai_egress_block_reason is None and after.ai_egress_block_reason is None)
    reports = p.storage.ReportStore(state / "reports.sqlite3")
    reports.save(before)
    require(reports.get(before.id) == before)
    store = p.baselines.BaselineStore(state / "baselines.sqlite3")
    baseline = store.save(before)
    require(store.latest("replay", "fixture", "disk") == baseline)
    after.comparison = p.baselines.compare(after, baseline)
    require(after.comparison.status == "compared")
    fields = {item.field: item for item in after.comparison.changes}
    for category in ("log", "business"):
        c = fields["disk_scope.category." + category + ".allocated_bytes"]
        require(int(c.after) > int(c.before))
    require(
        all(
            c.evidence_ids == ["E-DISK-RECLAIM"]
            for c in fields.values()
            if c.field.startswith("disk_scope")
        )
    )
    reports.save(after)
    require(reports.get(after.id) == after)
    markdown = p.main.report_markdown(reports.get(after.id))
    require("登记目录组合" in markdown and "业务数据（排除清理）" in markdown)
    private = [str(ROOT), "/proc/", *[name.split("/")[-1] for name in NAMES.values()]]
    serialized = baseline.model_dump_json() + after.model_dump_json() + markdown
    require(all(item not in serialized for item in private))
    require(
        "object_ref" not in baseline.model_dump_json()
        and "process-" not in baseline.model_dump_json()
    )
    summary = json.dumps(p.ai.explanation_input(after))
    require(
        all(item not in summary for item in [*private, "disk_scope", "directory-", "object_ref"])
    )
    unknown = dict(baseline.features)
    unknown["disk_scope.unknown"] = "512"
    rejected = False
    try:
        p.disk.validate_allocation_features(unknown)
    except p.disk.DiskAllocationRejected:
        rejected = True
    require(rejected)
    bad = report_for(p, raw, second, vfs)
    bad.comparison = p.baselines.compare(bad, baseline.model_copy(update={"features": unknown}))
    require(bad.comparison.status == "incomplete" and bad.comparison.changes == [])
    require(bad.ai_egress_block_reason == "unclassified_payload")
    rejected = False
    try:
        p.ai.explanation_input(bad)
    except ValueError:
        rejected = True
    require(rejected)
    drifted = report_for(p, drift_raw, drift, vfs)
    comparison = p.baselines.compare(drifted, baseline)
    require(comparison.status == "scope_changed" and comparison.changes == [])
    tampered = report_for(p, raw, second, vfs)
    tampered.comparison = p.models.BaselineComparison(
        status="compared",
        changes=[
            p.models.BaselineChange(
                field="disk_scope.unknown", before="0", after="512", evidence_ids=["E-DISK-RECLAIM"]
            )
        ],
    )
    for operation in (lambda: p.main.report_markdown(tampered), lambda: store.save(tampered)):
        rejected = False
        try:
            operation()
        except ValueError:
            rejected = True
        require(rejected)
    require(p.model_calls == [])
    return {
        "diagnosis": True,
        "report_save_readback": True,
        "baseline_save_readback": True,
        "same_scope_log_and_business_growth": True,
        "export": True,
        "unknown_metric_whole_comparison_rejected": True,
        "unknown_export_and_baseline_rejected": True,
        "scope_change_not_compared": True,
        "model_projection_closed": True,
        "zero_model_calls": True,
        "no_fixture_paths_or_names_exported": True,
    }


def by_size(value, size):
    rows = [row for row in value["objects"] if row["logical_bytes"] == size]
    require(len(rows) == 1)
    return rows[0]


def object_contract(first, second):
    sparse = by_size(first, SIZES["sparse"])
    require(0 < sparse["allocated_bytes"] < sparse["logical_bytes"])
    require(sparse["directory_refs"] == ["directory-1", "directory-3"])
    require(sparse["link_count"] == sparse["scoped_link_count"] == 2)
    require(sparse["holder_refs"] == ["process-1"] and sparse["state"] == "linked_open")
    require(by_size(first, SIZES["ordinary"])["state"] == "linked_open")
    deleted = by_size(first, SIZES["deleted_log"])
    require(deleted["state"] == "deleted_held" and deleted["link_count"] == 0)
    require(deleted["release_condition"] == "all_holders_close")
    mapped = by_size(first, SIZES["mapped"])
    require(mapped["state"] == "linked_no_registered_holder" and mapped["holder_refs"] == [])
    business = [r for r in first["objects"] if r["category"] == "business"]
    require(len(business) == 2 and any(r["state"] == "deleted_held" for r in business))
    require(
        all(
            r["conditional_upper_bytes"] == 0 and r["release_condition"] == "business_excluded"
            for r in business
        )
    )
    require(len(first["objects"]) == 7)
    require(
        sum(r["conditional_upper_bytes"] for r in first["objects"])
        == first["conditional_log_upper_bytes"]
    )
    require(second["conditional_log_upper_bytes"] > first["conditional_log_upper_bytes"])
    return {
        "sparse_allocation_below_logical": True,
        "cross_directory_hardlinks_deduplicated": True,
        "registered_regular_fd_state": True,
        "duplicate_fd_one_holder": True,
        "deleted_log_fd": True,
        "linked_and_deleted_business_excluded": True,
        "mmap_has_no_registered_fd": True,
    }


class LinuxReadOnlyMapping:
    """One fixed fake-file mapping, Linux x86_64 glibc ABI; never dereference it."""

    def __init__(self, fd):
        import ctypes

        require(sys.platform == "linux" and os.uname().machine == "x86_64", "holder_failed")
        require(sys.version_info >= (3, 12), "holder_failed")
        require(type(fd) is int and fd >= 0, "holder_failed")
        metadata = os.fstat(fd)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_size == SIZES["mapped"],
            "holder_failed",
        )
        require(
            ctypes.sizeof(ctypes.c_void_p) == 8
            and ctypes.sizeof(ctypes.c_size_t) == 8
            and ctypes.sizeof(ctypes.c_long) == 8
            and ctypes.sizeof(ctypes.c_int) == 4,
            "holder_failed",
        )
        self._ctypes = ctypes
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._libc.mmap.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_long,
        ]
        self._libc.mmap.restype = ctypes.c_void_p
        self._libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self._libc.munmap.restype = ctypes.c_int
        self._length = SIZES["mapped"]
        self.closed = True
        # PROT_READ=1, MAP_PRIVATE=2, offset=0; fd is only the freshly generated fake file.
        address = self._libc.mmap(None, self._length, 1, 2, fd, 0)
        require(address != ctypes.c_void_p(-1).value, "holder_failed")
        self._address = 0 if address is None else address
        self.closed = False

    def close(self):
        if not self.closed:
            require(
                self._libc.munmap(self._ctypes.c_void_p(self._address), self._length) == 0,
                "holder_failed",
            )
            self.closed = True
            self._address = None


def child_main():
    regular = {}
    mapping = None
    try:
        for key in ("sparse", "ordinary", "deleted_log", "deleted_business"):
            regular[key] = os.open(ROOT / NAMES[key], os.O_RDONLY | os.O_NOFOLLOW)
        regular["duplicate"] = os.dup(regular["sparse"])
        fd = os.open(ROOT / NAMES["mapped"], os.O_RDONLY | os.O_NOFOLLOW)
        try:
            mapping = LinuxReadOnlyMapping(fd)
        finally:
            os.close(fd)
        print('{"ready":true,"mmap_without_fd":true}', flush=True)
        for line in sys.stdin:
            command = line.strip()
            if command == "close_regular":
                for fd in regular.values():
                    os.close(fd)
                regular.clear()
                require(mapping is not None and not mapping.closed, "holder_failed")
                print('{"closed":true,"mapping_alive":true}', flush=True)
            elif command == "release_mapping":
                mapping.close()
                mapping = None
                print('{"mapping_released":true}', flush=True)
            elif command == "finish":
                print('{"finished":true}', flush=True)
                return 0
            else:
                return 1
    except BaseException:
        print('{"failed":true}', flush=True)
        return 1
    finally:
        for fd in regular.values():
            os.close(fd)
        if mapping is not None:
            mapping.close()
    return 1


class Holder:
    def __init__(self):
        self.process = subprocess.Popen(  # noqa: S603 -- fixed interpreter and this own child.
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--holder-child"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"LC_ALL": "C"},
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            require(self.read() == {"ready": True, "mmap_without_fd": True}, "holder_failed")
        except BaseException:
            self.close()
            raise

    def read(self):
        require(self.selector.select(10), "holder_failed")
        raw = self.process.stdout.readline(256)
        require(raw and len(raw) < 256, "holder_failed")
        try:
            return json.loads(raw)
        except ValueError:
            raise FixtureRejected("holder_failed") from None

    def command(self, command, expected):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        require(self.read() == expected, "holder_failed")

    def close(self):
        try:
            if self.process.poll() is None:
                self.command("finish", {"finished": True})
                self.process.wait(timeout=5)
        except BaseException:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            self.selector.close()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


def write_fake(path, size, sparse=False, append=False):
    require(path.is_relative_to(ROOT) and path != ROOT)
    flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_CREAT | os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        if sparse:
            os.ftruncate(fd, size)
            require(os.pwrite(fd, b"F" * 4096, 0) == 4096)
            require(os.pwrite(fd, b"F" * 4096, size - 4096) == 4096)
        else:
            block = b"F" * 65536
            while size:
                written = os.write(fd, block[: min(size, len(block))])
                require(written > 0)
                size -= written
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_owned_root():
    require(ROOT == Path("/var/tmp/oa-native-fixture-20261107"))  # noqa: S108, SIM300 -- preserve executed AST.
    require(ROOT.resolve() == ROOT and all(not p.is_symlink() for p in [ROOT, *ROOT.parents]))
    require(ROOT.is_dir() and not ROOT.is_symlink())
    fd = os.open(ROOT / ".fixture-owner", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode))
        require(os.read(fd, len(MARKER) + 1) == MARKER)
    finally:
        os.close(fd)
    for parent, dirs, files in os.walk(ROOT, followlinks=False):
        for name in [*dirs, *files]:
            entry = Path(parent) / name
            require(entry.is_relative_to(ROOT) and not entry.is_symlink())
    shutil.rmtree(ROOT)


def native_run(witness):
    require(
        sys.platform == "linux"
        and os.uname().machine == "x86_64"
        and sys.version_info >= (3, 13)
        and sys.flags.isolated == 1
        and os.geteuid() == 0,
        "profile_rejected",
    )
    require(not ROOT.exists() and not ROOT.is_symlink(), "root_exists")
    require(
        ROOT.parent.resolve() == ROOT.parent and all(not p.is_symlink() for p in ROOT.parents),
        "profile_rejected",
    )
    require(ROOT.parent.stat().st_dev == Path("/").stat().st_dev, "profile_rejected")
    require(os.statvfs(SOURCE).f_flag & os.ST_RDONLY, "profile_rejected")
    require(
        RESULT.parent.is_dir()
        and RESULT.parent.resolve() == RESULT.parent
        and all(not p.is_symlink() for p in RESULT.parents),
        "output_rejected",
    )
    require(not RESULT.exists() and not RESULT.is_symlink(), "output_rejected")
    holder = None
    created = False
    try:
        ROOT.mkdir(mode=0o700)
        created = True
        (ROOT / ".fixture-owner").write_bytes(MARKER)
        for name in ("logs-a", "logs-b", "business", "state"):
            (ROOT / name).mkdir(mode=0o700)
        p = load_product(SOURCE, ROOT / "state")
        observations = [statvfs_sample("before_files")]
        for key, size in SIZES.items():
            write_fake(ROOT / NAMES[key], size, sparse=key == "sparse")
        os.link(ROOT / NAMES["sparse"], ROOT / NAMES["sparse_alias"])
        observations.append(statvfs_sample("files_created"))
        holder = Holder()
        require(holder.process.pid != os.getpid())
        for key in ("deleted_log", "deleted_business"):
            (ROOT / NAMES[key]).unlink()
        observations.append(statvfs_sample("deleted_fds_still_held"))
        raw = make_scope(p.helper, holder.process.pid)
        first = p.helper.project(raw)
        closed_projection(p, raw, first)
        for key in ("growth_log", "business"):
            write_fake(ROOT / NAMES[key], 8 * MIB, append=True)
        second = p.helper.project(raw)
        closed_projection(p, raw, second)
        checks = object_contract(first, second)
        drift_raw = make_scope(p.helper, holder.process.pid, depth=1)
        drift = p.helper.project(drift_raw)
        checks.update(
            product_contract(
                p,
                ROOT / "state",
                raw,
                first,
                second,
                drift_raw,
                drift,
                statvfs_sample("product_envelope"),
            )
        )
        (ROOT / NAMES["ordinary"]).unlink()
        held = p.helper.project(raw)
        closed_projection(p, raw, held)
        require(by_size(held, SIZES["ordinary"])["state"] == "deleted_held")
        observations.append(statvfs_sample("before_regular_fd_close"))
        holder.command("close_regular", {"closed": True, "mapping_alive": True})
        observations.append(statvfs_sample("after_regular_fd_close"))
        closed = p.helper.project(raw)
        closed_projection(p, raw, closed)
        vanished = {SIZES[k] for k in ("ordinary", "deleted_log", "deleted_business")}
        require(all(r["logical_bytes"] not in vanished for r in closed["objects"]))
        allocated = by_size(closed, SIZES["mapped"])["allocated_bytes"]
        observations.append(statvfs_sample("before_mmap_unlink"))
        (ROOT / NAMES["mapped"]).unlink()
        invisible = p.helper.project(raw)
        closed_projection(p, raw, invisible)
        require(all(r["logical_bytes"] != SIZES["mapped"] for r in invisible["objects"]))
        observations.append(statvfs_sample("unlinked_mmap_still_held"))
        holder.command("release_mapping", {"mapping_released": True})
        observations.append(statvfs_sample("after_mmap_release"))
        checks.update(
            {
                "deleted_objects_vanish_after_own_fds_close": True,
                "mmap_only_object_invisible_after_unlink": True,
                "mmap_released_by_child": True,
            }
        )
        holder.close()
        holder = None
        witness.update(
            {
                "real_default_filesystem": True,
                "separate_child_holder": True,
                "product_transport": "replay",
                "ssh_executed": False,
                "installation_executed": False,
                "model_calls": 0,
                "os_release_envelope": "declared_fixture_ubuntu_24_04",
                "capacity_measurement": "statvfs_root_device",
            }
        )
        return {
            "schema": "opsark-disk-native-fixture/v1",
            "mode": "native",
            "status": "passed",
            "source_witness": witness,
            "checks": checks,
            "projections": [first, second, held, closed, invisible],
            "statvfs_observations": observations,
            "mmap_allocated_before_unlink_bytes": allocated,
            "uncertainty": {
                "non_atomic": True,
                "concurrent_df_noise_possible": True,
                "allocation_is_not_exact_physical_release": True,
                "physical_release_verified": False,
            },
        }
    finally:
        if holder is not None:
            holder.close()
        if created:
            remove_owned_root()


def fake_meta(inode, mode=stat.S_IFREG | 0o600, size=4096, blocks=8, links=1):
    return SimpleNamespace(
        st_dev=1,
        st_ino=inode,
        st_mode=mode,
        st_nlink=links,
        st_size=size,
        st_blocks=blocks,
        st_mtime_ns=1,
        st_ctime_ns=1,
        st_uid=0,
    )


class FakeFilesystem:
    """Pure data simulator: never stat/open/readlink/scandir or touch /proc."""

    def __init__(self, grow=False):
        self.stats = {"/": fake_meta(1, mode=stat.S_IFDIR | 0o700)}
        for i, name in enumerate(("logs-a", "business", "logs-b"), 2):
            self.stats[(ROOT / name).as_posix()] = fake_meta(i, mode=stat.S_IFDIR | 0o700)
        for i, (key, size) in enumerate(SIZES.items(), 10):
            info = fake_meta(
                i,
                size=size,
                blocks=16 if key == "sparse" else size // 512,
                links=0 if key.startswith("deleted") else 2 if key == "sparse" else 1,
            )
            if grow and key in {"growth_log", "business"}:
                info.st_size += 8 * MIB
                info.st_blocks += 8 * MIB // 512
                info.st_ctime_ns = 2
            self.stats[(ROOT / NAMES[key]).as_posix()] = info
        self.stats[(ROOT / NAMES["sparse_alias"]).as_posix()] = self.stats[
            (ROOT / NAMES["sparse"]).as_posix()
        ]
        self.fds = {
            str(i): (
                (ROOT / NAMES[k]).as_posix() + (" (deleted)" if k.startswith("deleted") else ""),
                self.stats[(ROOT / NAMES[k]).as_posix()],
            )
            for i, k in enumerate(
                ("sparse", "sparse", "ordinary", "deleted_log", "deleted_business"), 3
            )
        }
        for key in ("deleted_log", "deleted_business"):
            del self.stats[(ROOT / NAMES[key]).as_posix()]
        self.stats["/proc/101/fd"] = fake_meta(99, mode=stat.S_IFDIR | 0o500)

    def directory(self, path):
        require(path in self.stats)
        return path

    def child(self, parent, name):
        return parent + "/" + name

    def metadata(self, handle, name=None):
        return self.stats[handle if name is None else handle + "/" + name]

    def entries(self, handle):
        if handle == "/proc/101/fd":
            return sorted(self.fds)
        return sorted(
            p[len(handle) + 1 :]
            for p in self.stats
            if p.startswith(handle + "/") and "/" not in p[len(handle) + 1 :]
        )

    def fd_metadata(self, handle, name):
        require(handle == "/proc/101/fd")
        return self.fds[name]


def self_test(source, witness):
    with tempfile.TemporaryDirectory(prefix="fake-selftest-", dir=Path(__file__).parent) as local:
        p = load_product(source, Path(local))
        raw = make_scope(p.helper, 101)
        drift_raw = make_scope(p.helper, 101, depth=1)
        first = p.helper.project(raw, FakeFilesystem())
        second = p.helper.project(raw, FakeFilesystem(grow=True))
        drift = p.helper.project(drift_raw, FakeFilesystem(grow=True))
        closed_projection(p, raw, first)
        closed_projection(p, raw, second)
        checks = object_contract(first, second)
        checks.update(
            product_contract(
                p, Path(local), raw, first, second, drift_raw, drift, fake_vfs("product_envelope")
            )
        )
        witness.update(
            {
                "real_default_filesystem": False,
                "separate_child_holder": False,
                "product_transport": "replay",
                "ssh_executed": False,
                "installation_executed": False,
                "model_calls": 0,
                "os_release_envelope": "declared_fixture_ubuntu_24_04",
                "capacity_measurement": "fake_only",
            }
        )
        return {
            "schema": "opsark-disk-native-fixture/v1",
            "mode": "fake_self_test",
            "status": "passed",
            "source_witness": witness,
            "checks": checks,
            "native_executed": False,
        }


def emit_native(result):
    require(RESULT.parent.is_dir() and not RESULT.parent.is_symlink(), "output_rejected")
    require(not RESULT.exists() and not RESULT.is_symlink(), "output_rejected")
    fd = os.open(RESULT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(canonical(result))
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--native", action="store_true")
    modes.add_argument("--holder-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--source-root", type=Path, help="self-test only; reviewed public source")
    args = parser.parse_args()
    if args.holder_child:
        return child_main()
    os.environ.clear()
    os.environ.update({"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    if os.name == "nt":
        os.environ.update({"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"})
    sys.addaudithook(no_network)
    try:
        require(not args.native or args.source_root is None, "profile_rejected")
        source = SOURCE if args.native else args.source_root
        require(source is not None, "source_rejected")
        witness = verify_source(source)
        if args.native:

            def timeout(*_):
                raise FixtureRejected("native_failed")

            signal.signal(signal.SIGALRM, timeout)
            signal.alarm(90)
            result = native_run(witness)
            signal.alarm(0)
            emit_native(result)
        else:
            result = self_test(source, witness)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except BaseException as error:
        if hasattr(signal, "alarm"):
            signal.alarm(0)
        reason = (
            str(error)
            if isinstance(error, FixtureRejected) and str(error) in FAILURES
            else ("native_failed" if args.native else "self_test_failed")
        )
        sys.stdout.buffer.write(
            canonical(
                {"schema": "opsark-disk-native-fixture/v1", "status": "failed", "reason": reason}
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
