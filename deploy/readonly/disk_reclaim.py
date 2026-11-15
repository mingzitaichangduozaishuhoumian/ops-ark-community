#!/usr/bin/python3 -I
"""Bounded Linux inode/FD metadata projection. Never open file content."""

import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import cast

SCOPE = Path("/etc/opsark/disk-reclaim-scope.json")
MAX_SCOPE = 8192
MAX_OBJECTS = 32
MAX_ENTRIES = 512
MAX_FDS = 512
MAX_OUTPUT = 14000
REASONS = {
    "scope_invalid",
    "scope_unavailable",
    "path_untrusted",
    "scope_exceeded",
    "metadata_unavailable",
    "metadata_changed",
    "metadata_unsupported",
    "metadata_sensitive",
    "collection_limit",
    "collection_timeout",
    "object_unavailable",
}
SENSITIVE = re.compile(
    r"(?i)(?:^|[/_.-])(?:secret|token|password|passwd|credential|privatekey)(?:$|[/_.-])|"
    r"(?:^|/)\.env(?:$|\.)|\.(?:pem|key|p12|pfx)$|"
    r"(?:sk[-_][A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,})"
)


class Refused(ValueError):
    """Only closed codes may leave the target."""


def need(ok, reason="metadata_unavailable"):
    if not ok:
        raise Refused(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "scope_invalid")
            result[key] = value
        return result

    def constant(_):
        raise Refused("scope_invalid")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("scope_invalid") from None


def checked_scope(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SCOPE, "scope_invalid")
    value = strict(raw)
    need(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "directories",
            "process_ids",
            "max_depth",
        },
        "scope_invalid",
    )
    need(type(value["schema_version"]) is int and value["schema_version"] == 1, "scope_invalid")
    roots, pids, depth = value["directories"], value["process_ids"], value["max_depth"]
    need(type(roots) is list and 1 <= len(roots) <= 8, "scope_invalid")
    need(
        type(pids) is list
        and 1 <= len(pids) <= 32
        and all(type(pid) is int and 1 <= pid <= 2**22 for pid in pids)
        and pids == sorted(set(cast(list[int], pids))),
        "scope_invalid",
    )
    need(type(depth) is int and 0 <= depth <= 8, "scope_invalid")
    paths = []
    for root in roots:
        need(type(root) is dict and set(root) == {"path", "category"}, "scope_invalid")
        path = root["path"]
        need(
            type(path) is str
            and 1 <= len(path) <= 256
            and re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", path)
            and all(part not in {".", ".."} for part in PurePosixPath(path).parts)
            and not any(
                path == p or path.startswith(p + "/")
                for p in ("/proc", "/sys", "/dev", "/etc", "/root", "/run")
            )
            and type(root["category"]) is str
            and root["category"] in {"log", "business"},
            "scope_invalid",
        )
        need(not SENSITIVE.search(path), "metadata_sensitive")
        need(
            not any(
                path == old or path.startswith(old + "/") or old.startswith(path + "/")
                for old in paths
            ),
            "scope_invalid",
        )
        paths.append(path)
    return value


def trusted(metadata, directory=False):
    need(
        (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
        and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0,
        "path_untrusted",
    )


def load_scope(path=SCOPE):
    # Only this administrator-owned JSON is read. Data files never use read/open(O_RDONLY).
    for parent in reversed(path.parents):
        trusted(parent.lstat(), directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        trusted(meta)
        need(
            meta.st_mode & 0o077 == 0 and meta.st_nlink == 1 and 0 < meta.st_size <= MAX_SCOPE,
            "scope_invalid",
        )
        raw = os.read(fd, MAX_SCOPE + 1)
        need(len(raw) == meta.st_size, "metadata_changed")
        checked_scope(raw)
        return raw
    finally:
        os.close(fd)


def signature(meta):
    return (
        meta.st_dev,
        meta.st_ino,
        meta.st_mode,
        meta.st_nlink,
        meta.st_size,
        meta.st_blocks,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    )


class Filesystem:
    """Linux no-follow directory handles and stat only; injectable for local tests."""

    def __init__(self):
        self.stack = ExitStack()

    def close(self):
        self.stack.close()

    def _hold(self, fd):
        self.stack.callback(os.close, fd)
        return fd

    def directory(self, path):
        # Open each path component from /; never follow a service-controlled symlink.
        fd = self._hold(os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
        for part in PurePosixPath(path).parts[1:]:
            fd = self._hold(
                os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
                )
            )
        return fd

    def child(self, parent, name):
        return self._hold(
            os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
            )
        )

    def metadata(self, parent, name=None):
        return (
            os.fstat(parent)
            if name is None
            else os.stat(name, dir_fd=parent, follow_symlinks=False)
        )

    def entries(self, parent):
        with os.scandir(parent) as entries:
            # Bound materialization before sorting, including adversarial directories.
            names = []
            for entry in entries:
                need(len(names) < MAX_ENTRIES, "collection_limit")
                names.append(entry.name)
        return sorted(names)

    def fd_metadata(self, parent, name):
        # Follow only the kernel's proc FD magic link, never the returned target path.
        path = os.readlink(name, dir_fd=parent)
        meta = os.stat(name, dir_fd=parent, follow_symlinks=True)
        need(path == os.readlink(name, dir_fd=parent), "metadata_changed")
        return path, meta


def project(raw, fs=None, *, clock=time.monotonic, locate_ref=None, expected_snapshot=None):
    scope = checked_scope(raw)
    own = fs is None
    fs = Filesystem() if own else fs
    deadline = clock() + 3.5
    objects, roots, validations = {}, [], []
    entries_seen = fds_seen = 0

    def tick():
        need(clock() < deadline, "collection_timeout")

    def check_name(name):
        need(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", name)
            and name not in {".", ".."},
            "metadata_unsupported",
        )
        need(not SENSITIVE.search(name), "metadata_sensitive")

    def remember(meta, root, alias=False, holder=None, location=None):
        need(
            stat.S_ISREG(meta.st_mode)
            and 0 <= meta.st_size <= 2**63 - 1
            and 0 <= meta.st_blocks <= (2**63 - 1) // 512
            and 0 <= meta.st_nlink <= MAX_ENTRIES,
            "metadata_unsupported",
        )
        key = (meta.st_dev, meta.st_ino)
        if key not in objects:
            need(len(objects) < MAX_OBJECTS, "collection_limit")
            objects[key] = {
                "meta": meta,
                "roots": set(),
                "category": roots[root - 1][0]["category"],
                "aliases": 0,
                "holders": set(),
                "locations": [],
            }
        obj = objects[key]
        need(obj["category"] == roots[root - 1][0]["category"], "scope_exceeded")
        obj["roots"].add(root)
        need(signature(obj["meta"]) == signature(meta), "metadata_changed")
        obj["aliases"] += int(alias)
        if holder:
            obj["holders"].add(holder)
        if locate_ref is not None and location is not None:
            obj["locations"].append(location)

    def walk(handle, root, device, depth, path):
        nonlocal entries_seen
        tick()
        start = fs.metadata(handle)
        need(stat.S_ISDIR(start.st_mode) and start.st_dev == device, "scope_exceeded")
        validations.append((handle, None, signature(start)))
        for name in fs.entries(handle):
            tick()
            entries_seen += 1
            need(entries_seen <= MAX_ENTRIES, "collection_limit")
            check_name(name)
            meta = fs.metadata(handle, name)
            need(meta.st_dev == device, "scope_exceeded")
            validations.append((handle, name, signature(meta)))
            if stat.S_ISDIR(meta.st_mode):
                need(depth < scope["max_depth"], "collection_limit")
                child = fs.child(handle, name)
                need(signature(fs.metadata(child)) == signature(meta), "metadata_changed")
                walk(child, root, device, depth + 1, path + "/" + name)
            elif stat.S_ISREG(meta.st_mode):
                remember(
                    meta,
                    root,
                    alias=True,
                    location={"kind": "linked_path", "path": path + "/" + name},
                )
            else:
                raise Refused("metadata_unsupported")

    try:
        root_device = fs.metadata(fs.directory("/")).st_dev
        for index, root in enumerate(scope["directories"], 1):
            tick()
            handle = fs.directory(root["path"])
            meta = fs.metadata(handle)
            need(meta.st_dev == root_device, "scope_exceeded")
            roots.append((root, meta.st_dev))
            walk(handle, index, meta.st_dev, 0, root["path"])
        for index, pid in enumerate(scope["process_ids"], 1):
            tick()
            handle = fs.directory("/proc/" + str(pid) + "/fd")
            names = fs.entries(handle)
            for name in names:
                tick()
                fds_seen += 1
                need(
                    fds_seen <= MAX_FDS and name.isascii() and name.isdecimal(), "collection_limit"
                )
                target, meta = fs.fd_metadata(handle, name)
                if not stat.S_ISREG(meta.st_mode):
                    # Pipes, sockets, devices and kernel anonymous descriptors have no regular
                    # file allocation claim. No target string ever leaves this function.
                    need(
                        any(
                            test(meta.st_mode)
                            for test in (stat.S_ISFIFO, stat.S_ISSOCK, stat.S_ISCHR, stat.S_ISBLK)
                        )
                        or target.startswith("anon_inode:"),
                        "metadata_unsupported",
                    )
                    continue
                need(not SENSITIVE.search(target), "metadata_sensitive")
                deleted = meta.st_nlink == 0
                if deleted:
                    need(target.endswith(" (deleted)"), "metadata_changed")
                    target = target[:-10]
                matches = [
                    i
                    for i, (root, dev) in enumerate(roots, 1)
                    if target.startswith(root["path"] + "/") and meta.st_dev == dev
                ]
                need(len(matches) == 1, "scope_exceeded")
                root = matches[0]
                relative = target[len(roots[root - 1][0]["path"]) + 1 :]
                need(str(PurePosixPath(target)) == target, "scope_exceeded")
                need(len(PurePosixPath(relative).parts) <= scope["max_depth"] + 1, "scope_exceeded")
                for part in PurePosixPath(relative).parts:
                    check_name(part)
                if not deleted:
                    # A linked FD must also be the inode observed by the bounded tree walk.
                    need((meta.st_dev, meta.st_ino) in objects, "metadata_changed")
                remember(
                    meta,
                    root,
                    holder="process-" + str(index),
                    location={
                        "kind": "deleted_descriptor" if deleted else "open_descriptor",
                        "last_path": target,
                        "pid": pid,
                        "fd": int(name),
                    },
                )
                validations.append((handle, name, (target, signature(meta), deleted)))
            # Reused/closed/added FDs make the entire snapshot unavailable.
            need(names == fs.entries(handle), "metadata_changed")
        for handle, name, expected in validations:
            tick()
            if len(expected) == 3:
                target, meta = fs.fd_metadata(handle, name)
                if expected[2] and target.endswith(" (deleted)"):
                    target = target[:-10]
                need((target, signature(meta), meta.st_nlink == 0) == expected, "metadata_changed")
            else:
                need(signature(fs.metadata(handle, name)) == expected, "metadata_changed")
        rows = []
        conditional_log_upper_bytes = 0
        scope_digest = digest(raw)
        for key, obj in sorted(objects.items()):
            meta = obj["meta"]
            category = obj["category"]
            need(obj["aliases"] <= meta.st_nlink, "metadata_changed")
            deleted = meta.st_nlink == 0
            complete_links = obj["aliases"] == meta.st_nlink
            upper = meta.st_blocks * 512 if category == "log" and complete_links else 0
            conditional_log_upper_bytes += upper
            rows.append(
                {
                    "object_ref": digest(canonical([scope_digest, *key, meta.st_ctime_ns])),
                    "directory_refs": ["directory-" + str(root) for root in sorted(obj["roots"])],
                    "category": category,
                    "logical_bytes": meta.st_size,
                    "allocated_bytes": meta.st_blocks * 512,
                    "link_count": meta.st_nlink,
                    "scoped_link_count": obj["aliases"],
                    "holder_refs": sorted(obj["holders"]),
                    "state": "deleted_held"
                    if deleted
                    else ("linked_open" if obj["holders"] else "linked_no_registered_holder"),
                    "release_condition": "business_excluded"
                    if category == "business"
                    else (
                        "all_holders_close"
                        if deleted
                        else (
                            "retention_all_links_all_holders"
                            if complete_links
                            else "unscoped_links_unknown"
                        )
                    ),
                    "conditional_upper_bytes": upper,
                }
            )
        result = {
            "schema": "opsark-disk-reclaim/v1",
            "scope_digest": scope_digest,
            "snapshot_atomic": False,
            "holder_coverage": "registered_processes_only",
            "filesystem_coverage": "root_device_only",
            "physical_reclaim_verified": False,
            "immediate_reclaimable_bytes": None,
            "conditional_lower_bytes": 0,
            "conditional_log_upper_bytes": conditional_log_upper_bytes,
            "objects": rows,
            "actions_enabled": False,
        }
        result["snapshot_digest"] = digest(canonical(result))
        need(len(canonical(result)) <= MAX_OUTPUT, "collection_limit")
        if locate_ref is not None:
            need(result["snapshot_digest"] == expected_snapshot, "metadata_changed")
            matches = [
                (key, row)
                for key, row in zip(sorted(objects), rows, strict=True)
                if row["object_ref"] == locate_ref
            ]
            need(len(matches) == 1, "object_unavailable")
            key, row = matches[0]
            result = {
                "schema": "opsark-disk-object-location-local/v1",
                "scope_digest": scope_digest,
                "snapshot_digest": result["snapshot_digest"],
                "object_ref": row["object_ref"],
                "locations": objects[key]["locations"],
                "actions_enabled": False,
                "administrator_local_only": True,
            }
            need(len(canonical(result)) <= MAX_OUTPUT, "collection_limit")
        return result
    finally:
        if own:
            fs.close()


def locate(raw, object_ref, expected_scope, expected_snapshot, fs=None):
    """Administrator local-only mapping. Never allowlisted by SSH or accepted as evidence."""
    need(
        all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in (object_ref, expected_scope, expected_snapshot)
        ),
        "scope_invalid",
    )
    need(digest(raw) == expected_scope, "scope_invalid")
    return project(raw, fs, locate_ref=object_ref, expected_snapshot=expected_snapshot)


def main(arguments=None):
    try:
        arguments = sys.argv[1:] if arguments is None else arguments
        local = len(arguments) == 6 and [arguments[0], arguments[2], arguments[4]] == [
            "--locate-ref",
            "--expected-scope-sha256",
            "--expected-snapshot-sha256",
        ]
        need(not arguments or local, "scope_invalid")
        need(
            hasattr(os, "geteuid")
            and os.geteuid() == 0
            and all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")),
            "path_untrusted",
        )

        def timed_out(_signal, _frame):
            raise Refused("collection_timeout")

        signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, 4.0)
        raw = load_scope()
        result = locate(raw, arguments[1], arguments[3], arguments[5]) if local else project(raw)
        code = 0
    except Refused as error:
        reason = str(error) if str(error) in REASONS else "metadata_unavailable"
        result = {
            "schema": "opsark-disk-reclaim-error/v1",
            "reason": reason,
            "actions_enabled": False,
        }
        code = 1
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        result = {
            "schema": "opsark-disk-reclaim-error/v1",
            "reason": "metadata_unavailable",
            "actions_enabled": False,
        }
        code = 1
    finally:
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.buffer.write(canonical(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
