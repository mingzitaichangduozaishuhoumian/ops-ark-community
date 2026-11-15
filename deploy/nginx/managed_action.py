"""One independently approved, locally registered Nginx upstream action."""

import hmac
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

_INSTALL_ROOT = Path("/usr/local/lib/opsark-nginx-action")
if __name__ == "__main__":
    _entry = _INSTALL_ROOT / "deploy/nginx/managed_action.py"
    try:
        if (
            sys.platform != "linux"
            or os.geteuid() != 0
            or Path(__file__) != _entry
            or not sys.flags.isolated
            or not sys.dont_write_bytecode
        ):
            raise ValueError
        for _path in _entry.parents:
            _info = _path.lstat()
            if _info.st_uid != 0 or _info.st_mode & 0o022 or not stat.S_ISDIR(_info.st_mode):
                raise ValueError
        for _file in (
            "deploy/__init__.py",
            "deploy/nginx/__init__.py",
            "deploy/nginx/managed_action.py",
            "deploy/nginx/managed_context.py",
            "deploy/nginx/managed_runtime.py",
            "deploy/nginx/managed_startup.py",
            "deploy/nginx/action_journal.py",
            "deploy/nginx/config_snapshot.py",
            "deploy/readonly/__init__.py",
            "deploy/readonly/nginx_dependencies.py",
        ):
            _path = _INSTALL_ROOT / _file
            _info = _path.lstat()
            _parent = _path.parent.lstat()
            if (
                _info.st_uid != 0
                or not stat.S_ISREG(_info.st_mode)
                or _info.st_nlink != 1
                or _info.st_mode & 0o022
                or (_path.name == "__init__.py" and _info.st_size != 0)
                or not stat.S_ISDIR(_parent.st_mode)
                or _parent.st_uid != 0
                or _parent.st_mode & 0o022
            ):
                raise ValueError
        # The installation directory contains only the reviewed package files.
        sys.path.insert(0, str(_INSTALL_ROOT))
    except (OSError, ValueError):
        sys.stderr.write("Nginx action entry refused.\n")
        raise SystemExit(126) from None

from deploy.nginx import action_journal as journal  # noqa: E402 - verify install root before imports.
from deploy.nginx import config_snapshot as snapshot  # noqa: E402
from deploy.nginx import managed_context as context  # noqa: E402
from deploy.nginx import managed_runtime as runtime  # noqa: E402

MAX_WIRE = 8192
_ID = re.compile(r"[a-f0-9]{32}\Z")
_SITE = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
_UPSTREAM = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_OPS = {
    "prepare": {"plan_id", "mode_revision"},
    "plan_status": {"plan_id"},
    "submit": {"plan_id", "action_id", "plan_digest", "approval_id", "mode_revision"},
    "status": {"action_id"},
    "reconcile_status": {"action_id", "plan_id", "plan_digest", "mode_revision"},
    "observe": {"action_id"},
    "rollback_prepare": {"plan_id", "original_action_id", "mode_revision"},
}
_PLAN_FIELDS = {
    "schema_version",
    "status",
    "plan_id",
    "action",
    "action_id",
    "policy_digest",
    "plan_digest",
    "mode_revision",
    "source_sha256",
    "candidate_sha256",
    "backup_sha256",
    "context_sha256",
    "expires_at",
    "upstream_before",
    "upstream_after",
    "affected_site_ids",
    "syntax",
    "original_action_id",
}
_PRIVATE_FIELDS = {
    "machine_sha256",
    "master_sha256",
    "source_identity",
    "backup_plan_id",
    "backup_manifest_sha256",
    "non_target_context_sha256",
}
_DISK_PREVIOUS = "disk_published_live_previous"
_REASONS = {
    "policy_refused",
    "scope_changed",
    "syntax_refused",
    "expired",
    "busy",
    "business_unconfirmed",
    "conflict",
    "not_found",
    "operation_unconfirmed",
}


def _is_id(value) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _revision(value) -> bool:
    return type(value) is int and 0 <= value <= 2**53 - 1


def parse_request(raw: bytes) -> dict:
    context.require(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE)
    body = context.strict_json(raw)
    context.require(type(body) is dict and type(body.get("op")) is str and body["op"] in _OPS)
    fields = _OPS[body["op"]]
    context.require(
        set(body) == {"schema_version", "op", "policy_digest"} | fields
        and type(body["schema_version"]) is int
        and body["schema_version"] == 1
        and context.hex_digest(body["policy_digest"])
    )
    for name in fields:
        value = body[name]
        if name == "mode_revision":
            valid = _revision(value)
        elif name in {"plan_id", "approval_id"}:
            valid = _is_id(value)
        else:
            valid = context.hex_digest(value)
        context.require(valid)
    return body


@dataclass(frozen=True)
class Plan:
    view: dict
    private: dict
    candidate: bytes
    retired: bool = False

    @property
    def is_restore(self) -> bool:
        return self.view["action"] == "restore"

    @property
    def restore_disk_only(self) -> bool:
        return self.private.get("restore_disk_only") is True


def _plan_digest(view: dict, private: dict) -> str:
    return context.digest(
        context.canonical(
            {
                "kind": "opsark-managed-nginx-plan-v1",
                "view": {k: v for k, v in view.items() if k != "plan_digest"},
                "private": private,
            }
        )
    )


def _plan_from_record(identifier: str, envelope: dict, data: bytes | None) -> Plan:
    context.require(type(envelope) is dict and set(envelope) == {"view", "private"})
    view, private = envelope["view"], envelope["private"]
    context.require(
        type(view) is dict
        and set(view) == _PLAN_FIELDS
        and type(private) is dict
        and set(private) - {"restore_disk_only", "startup_sha256"} == _PRIVATE_FIELDS
        and type(private.get("restore_disk_only", False)) is bool
        and ("startup_sha256" not in private or context.hex_digest(private["startup_sha256"]))
    )
    context.require(
        type(view["schema_version"]) is int
        and view["schema_version"] == 1
        and view["status"] == "ready"
        and view["syntax"] == "passed"
        and view["plan_id"] == identifier
        and view["action"] in {"apply", "restore"}
        and view["action_id"] == journal.action_id(identifier, view["action"])
        and _revision(view["mode_revision"])
    )
    context.require(
        all(
            context.hex_digest(view[key])
            for key in (
                "policy_digest",
                "plan_digest",
                "source_sha256",
                "candidate_sha256",
                "backup_sha256",
                "context_sha256",
            )
        )
        and all(
            context.hex_digest(private[key])
            for key in (
                "machine_sha256",
                "master_sha256",
                "backup_manifest_sha256",
                "non_target_context_sha256",
            )
        )
        and _is_id(private["backup_plan_id"])
        and snapshot._trusted_identity(private["source_identity"], snapshot.DEFAULT_POLICY)
    )
    context.require(
        view["source_sha256"] != view["candidate_sha256"]
        and (data is None or view["candidate_sha256"] == context.digest(data))
        and hmac.compare_digest(view["plan_digest"], _plan_digest(view, private))
    )
    context.utc(view["expires_at"])
    sites = view["affected_site_ids"]
    context.require(
        type(sites) is list
        and 1 <= len(sites) <= 8
        and all(type(site) is str and _SITE.fullmatch(site) for site in sites)
        and sites == sorted({site for site in sites if type(site) is str})
    )
    for key in ("upstream_before", "upstream_after"):
        match = _UPSTREAM.fullmatch(view[key]) if type(view[key]) is str else None
        context.require(match is not None and int(match[1]) <= 65535)
    context.require(view["upstream_before"] != view["upstream_after"])
    if view["action"] == "apply":
        context.require(
            view["original_action_id"] is None
            and private["backup_plan_id"] == identifier
            and view["backup_sha256"] == view["source_sha256"]
            and not private.get("restore_disk_only", False)
        )
    else:
        context.require(
            view["original_action_id"] == journal.action_id(private["backup_plan_id"], "apply")
            and private["backup_plan_id"] != identifier
            and view["backup_sha256"] == view["candidate_sha256"]
        )
    return Plan(view, private, data if data is not None else b"", retired=data is None)


_RETIRED = ".expired"
_RETIRING = ".retiring-"
_DISCARDING = ".discarding-"
_ARCHIVE_SEAL = "archive_sha256"


def _read_retired_plan(directory: int, identifier: str) -> Plan | None:
    record = journal._record(directory, identifier + ".json", _ARCHIVE_SEAL)
    if record is None:
        return None
    context.require(set(record) == {"schema_version", "view", "private", _ARCHIVE_SEAL})
    context.require(type(record["schema_version"]) is int and record["schema_version"] == 1)
    return _plan_from_record(identifier, {key: record[key] for key in ("view", "private")}, None)


def _load_retired_plan(identifier: str) -> Plan | None:
    path = context.PRIVATE_ROOT / "plans" / _RETIRED
    try:
        with snapshot._directory(path, snapshot.DEFAULT_POLICY, private=True) as directory:
            return _read_retired_plan(directory, identifier)
    except FileNotFoundError:
        return None


def _load_active_plan(identifier: str) -> Plan | None:
    try:
        raw, data = snapshot._read_bundle(
            context.PRIVATE_ROOT / "plans" / identifier, "candidate.conf", snapshot.DEFAULT_POLICY
        )
    except FileNotFoundError:
        return None
    return _plan_from_record(identifier, context.strict_json(raw), data)


def _load_plan(identifier: str) -> Plan | None:
    context.require(_is_id(identifier))
    retired = _load_retired_plan(identifier)
    if retired is not None:
        return retired
    try:
        active = _load_active_plan(identifier)
    except snapshot.SnapshotError:
        # A status read may overlap a locked retirement after it opened the bundle.
        retired = _load_retired_plan(identifier)
        if retired is not None:
            return retired
        raise
    return active if active is not None else _load_retired_plan(identifier)


def _retirement_matches(plan: Plan) -> bool:
    # Check again under the action lock. A submit may have read the active plan
    # before retirement and the host clock may since have moved backwards.
    identifier = plan.view["plan_id"]
    if _load_retired_plan(identifier) is None:
        context.require(not plan.retired, "scope_changed")
        return False
    # An interrupted rename can make an archive visible before it is durable.
    path = context.PRIVATE_ROOT / "plans" / _RETIRED
    with journal._directory(path, durable=True) as directory:
        archived = _read_retired_plan(directory, identifier)
        context.require(
            archived is not None
            and archived.view == plan.view
            and archived.private == plan.private,
            "scope_changed",
        )
        os.fsync(directory)
    return True


def _checked_plan(identifier: str, policy_digest: str) -> Plan:
    plan = _load_plan(identifier)
    if plan is None:
        raise context.Refused("not_found")
    context.require(hmac.compare_digest(plan.view["policy_digest"], policy_digest), "scope_changed")
    return plan


def _plan_error(request: dict, status: str, reason: str) -> dict:
    return {
        "schema_version": 1,
        "status": status,
        "policy_digest": request["policy_digest"],
        "plan_id": request["plan_id"],
        "reason": reason,
    }


def _action_response(
    request: dict,
    status: str,
    reason: str | None,
    *,
    plan: Plan | None = None,
    reconciled: str | None = None,
) -> dict:
    view = plan.view if plan is not None else {}
    return {
        "schema_version": 1,
        "status": status,
        "action_id": request["action_id"],
        "action": view.get("action"),
        "policy_digest": request["policy_digest"],
        "plan_id": view.get("plan_id"),
        "plan_digest": view.get("plan_digest"),
        "mode_revision": view.get("mode_revision"),
        "reason": reason,
        "reconciliation_status": reconciled,
    }


def _journal() -> journal.ActionJournal:
    return journal.ActionJournal(context.PRIVATE_ROOT / "actions")


def _reclaim_entries(directory: int, *, plans: bool) -> tuple[set[str], dict[str, bool]]:
    active: set[str] = set()
    retiring: dict[str, bool] = {}
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, start=1):
            context.require(count <= 34, "busy")
            name = entry.name
            if plans and name == _RETIRED:
                continue
            identifier = name.removeprefix(_RETIRING).removeprefix(_DISCARDING)
            context.require(
                _is_id(identifier)
                and name
                in (
                    identifier,
                    _RETIRING + identifier,
                    _DISCARDING + identifier,
                )
            )
            if name == identifier:
                active.add(identifier)
            else:
                context.require(identifier not in retiring)
                retiring[identifier] = name.startswith(_DISCARDING)
    context.require(active.isdisjoint(retiring))
    return active, retiring


def _reclaim_members(kind: str, directory: int, *, pending: bool) -> list[str]:
    member = "candidate.conf" if kind == "plans" else snapshot._CONFIG
    limits = {member: snapshot.MAX_CONFIG_BYTES, snapshot._MANIFEST: snapshot.MAX_MANIFEST_BYTES}
    if pending:
        limits[snapshot._PENDING_MANIFEST] = snapshot.MAX_MANIFEST_BYTES
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            context.require(entry.name in limits)
            info = entry.stat(follow_symlinks=False)
            context.require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == snapshot.DEFAULT_POLICY.owner_uid
                and not info.st_mode & 0o7077
                and info.st_nlink == 1
                and 0 <= info.st_size <= limits[entry.name]
            )
            names.append(entry.name)
    return names


def _unpublished_bundle(kind: str, identifier: str) -> bool:
    # Snapshot publication installs the final manifest last. The action lock
    # proves no cooperating publisher can still be writing these staged files.
    with snapshot._directory(
        context.PRIVATE_ROOT / kind / identifier, snapshot.DEFAULT_POLICY, private=True
    ) as directory:
        return snapshot._MANIFEST not in _reclaim_members(kind, directory, pending=True)


def _reclaim_directory(kind: str, directory: int, identifier: str, *, unpublished: bool) -> None:
    name = (_DISCARDING if unpublished else _RETIRING) + identifier
    with snapshot._directory(
        context.PRIVATE_ROOT / kind / name, snapshot.DEFAULT_POLICY, private=True
    ) as retiring:
        marker = os.fstat(retiring)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        context.require((marker.st_dev, marker.st_ino) == (current.st_dev, current.st_ino))
        names = _reclaim_members(kind, retiring, pending=unpublished)
        context.require(not unpublished or snapshot._MANIFEST not in names)
        # Re-fsync on resume as well, before deleting anything through the new name.
        os.fsync(directory)
        for item in names:
            os.unlink(item, dir_fd=retiring)
        os.fsync(retiring)
    os.rmdir(name, dir_fd=directory)
    os.fsync(directory)


def _stage_reclaim(
    kind: str, directory: int, identifier: str, *, unpublished: bool = False
) -> None:
    name = (_DISCARDING if unpublished else _RETIRING) + identifier
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise context.Refused("scope_changed")
    os.rename(identifier, name, src_dir_fd=directory, dst_dir_fd=directory)
    _reclaim_directory(kind, directory, identifier, unpublished=unpublished)


def _archive_plan(directory: int, plan: Plan) -> None:
    identifier = plan.view["plan_id"]
    with suppress(FileExistsError):
        os.mkdir(_RETIRED, mode=0o700, dir_fd=directory)
    with journal._directory(context.PRIVATE_ROOT / "plans" / _RETIRED, durable=True) as archive:
        record = {"schema_version": 1, "view": plan.view, "private": plan.private}
        name = identifier + ".json"
        prior = journal._record(archive, name, _ARCHIVE_SEAL)
        if prior is None:
            raw = journal._canonical({**record, _ARCHIVE_SEAL: "0" * 64})
            context.require(len(raw) + 1 <= journal._MAX_RECORD)
            journal._publish(archive, name, record, _ARCHIVE_SEAL)
        else:
            context.require(prior == {**record, _ARCHIVE_SEAL: journal._digest(record)})
            os.fsync(archive)


def _reclaim_previews(tx: journal._Transaction, now: datetime, *, backups: bool = True) -> None:
    root = context.PRIVATE_ROOT
    policy = snapshot.DEFAULT_POLICY
    with snapshot._directory(root / "plans", policy, private=True) as plans_fd:
        plan_ids, retiring_plans = _reclaim_entries(plans_fd, plans=True)
        plans = {}
        unpublished_plans = set()
        for identifier in sorted(plan_ids):
            try:
                plan = _load_active_plan(identifier)
            except snapshot.SnapshotError:
                plan = None
            if plan is None:
                context.require(_unpublished_bundle("plans", identifier))
                unpublished_plans.add(identifier)
            else:
                plans[identifier] = plan
        referenced = {p.private["backup_plan_id"] for p in plans.values() if p.is_restore}
        for identifier, unpublished in sorted(retiring_plans.items()):
            context.require(identifier not in referenced)
            if not unpublished:
                context.require(_load_retired_plan(identifier) is not None)
            context.require(not _has_plan_intent(tx, identifier), "scope_changed")
            _reclaim_directory("plans", plans_fd, identifier, unpublished=unpublished)
        for identifier in sorted(unpublished_plans):
            context.require(identifier not in referenced)
            context.require(not _has_plan_intent(tx, identifier), "scope_changed")
            _stage_reclaim("plans", plans_fd, identifier, unpublished=True)
        for identifier, plan in plans.copy().items():
            if identifier in referenced or _has_plan_intent(tx, identifier):
                continue
            retired = _load_retired_plan(identifier)
            if retired is None and now < context.utc(plan.view["expires_at"]):
                continue
            _archive_plan(plans_fd, plan)
            _stage_reclaim("plans", plans_fd, identifier)
            del plans[identifier]

    if not backups:
        return
    needed_backups = {plan.private["backup_plan_id"] for plan in plans.values()}
    with snapshot._directory(root / "backups", policy, private=True) as backups_fd:
        backup_ids, retiring_backups = _reclaim_entries(backups_fd, plans=False)
        for identifier in sorted(retiring_backups.keys() | backup_ids):
            needed = identifier in needed_backups or _has_plan_intent(tx, identifier)
            if identifier in retiring_backups:
                context.require(not needed)
                _reclaim_directory(
                    "backups", backups_fd, identifier, unpublished=retiring_backups[identifier]
                )
            elif not needed:
                unpublished = _unpublished_bundle("backups", identifier)
                if not unpublished:
                    _, manifest, _ = snapshot._backup(root / "backups" / identifier, policy)
                    context.require(
                        manifest["machine_sha256"] == snapshot._machine(policy), "scope_changed"
                    )
                _stage_reclaim("backups", backups_fd, identifier, unpublished=unpublished)


def _has_plan_intent(tx: journal._Transaction, identifier: str) -> bool:
    return any(
        tx.intent_binding(journal.action_id(identifier, operation)) is not None
        for operation in ("apply", "restore")
    )


def _plan_capacity(identifier: str, *, restore: bool) -> None:
    # Leave room for recovery even when normal previews used their whole budget.
    limits = {"plans": 32} if restore else {"plans": 24, "backups": 24}
    for name, limit in limits.items():
        path = context.PRIVATE_ROOT / name
        with (
            snapshot._directory(path, snapshot.DEFAULT_POLICY, private=True) as directory,
            os.scandir(directory) as entries,
        ):
            other_ids = (entry for entry in entries if entry.name not in (identifier, _RETIRED))
            for count, _entry in enumerate(other_ids, start=1):
                context.require(count < limit, "busy")


def _admit_plan_capacity(tx: journal._Transaction, identifier: str, *, restore: bool) -> None:
    if restore:
        try:
            _plan_capacity(identifier, restore=True)
        except context.Refused as error:
            if error.args != ("busy",):
                raise
        else:
            return
    _reclaim_previews(tx, datetime.now(UTC), backups=not restore)
    _plan_capacity(identifier, restore=restore)


def _receipt_for(request: dict, binding: dict, receipt: journal.ActionReceipt, plan: Plan) -> dict:
    context.require(
        plan.view["policy_digest"] == request["policy_digest"]
        and plan.view["action_id"] == request["action_id"]
        and binding["plan_id"] == plan.view["plan_id"]
        and binding["plan_sha256"] == plan.view["plan_digest"]
        and binding["action"] == plan.view["action"]
        and binding["source_sha256"] == plan.view["source_sha256"]
        and binding["candidate_sha256"] == plan.view["candidate_sha256"],
        "scope_changed",
    )
    status = receipt["status"]
    return _action_response(
        request,
        status,
        None if status == "verified" else "operation_unconfirmed",
        plan=plan,
        reconciled=receipt.get("reconciliation_status"),
    )


def _historical_status(request: dict) -> dict:
    # Read immutable records directly, without taking a write lock, reading the live
    # configuration or requiring the original policy to still be enabled.
    with journal._directory(context.PRIVATE_ROOT / "actions") as directory:
        evidence = journal._lookup(directory, request["action_id"])
    if evidence is None:
        return _action_response(request, "missing", "not_found")
    receipt = journal._current_receipt(evidence)
    assert receipt is not None  # noqa: S101 - a durable intent was checked above.
    binding = evidence["intent"]
    plan = _checked_plan(binding["plan_id"], request["policy_digest"])
    if request["op"] == "submit":
        context.require(_binding_matches(request, plan), "scope_changed")
        if binding["approval_id"] != request["approval_id"]:
            return _action_response(request, "refused", "conflict", plan=plan)
    return _receipt_for(request, binding, receipt, plan)


def _reconcile_status(request: dict, plan: Plan) -> dict:
    context.require(_binding_matches(request, plan), "scope_changed")
    identifier = plan.view["action_id"]
    with _journal().locked() as tx:
        receipt = tx.status(identifier)
        if receipt is not None:
            binding = tx.intent_binding(identifier)
            assert binding is not None  # noqa: S101 - the checked prior intent exists.
            return _receipt_for(request, binding, receipt, plan)
        if _retirement_matches(plan):
            return _action_response(request, "not_started", "expired", plan=plan)
        expired = datetime.now(UTC) >= context.utc(plan.view["expires_at"])
        if not expired and not tx.unstarted(identifier):
            return _action_response(request, "missing", "not_found")
        tx.close_unstarted(plan.view["plan_id"], plan.view["action"], plan.view["plan_digest"])
        return _action_response(request, "not_started", "expired", plan=plan)


def _trusted_backup(identifier: str, policy: context.Policy):
    data, manifest, raw_sha = snapshot._backup(
        context.PRIVATE_ROOT / "backups" / identifier, snapshot.DEFAULT_POLICY
    )
    context.require(
        manifest["source_name"] == policy.target_file
        and manifest["machine_sha256"] == snapshot._machine(snapshot.DEFAULT_POLICY),
        "scope_changed",
    )
    return data, manifest, raw_sha


def _capture_backup(identifier: str, policy: context.Policy, graph: context.Graph):
    try:
        data, manifest, raw_sha = _trusted_backup(identifier, policy)
    except FileNotFoundError:
        path = context.PRIVATE_ROOT / "backups" / identifier
        snapshot.capture(
            context.CONFIG_ROOT / policy.target, context.digest(graph.files[policy.target]), path
        )
        data, manifest, raw_sha = _trusted_backup(identifier, policy)
    context.require(
        data == graph.files[policy.target]
        and manifest["source_identity"] == graph.identities[policy.target],
        "scope_changed",
    )
    return data, raw_sha


def _verify_startup(plan: Plan, policy, graph, master, *, require_full: bool = False) -> str:
    origin = plan.private.get("startup_sha256")
    context.require(context.hex_digest(origin), "scope_changed")
    actual = runtime.require_started(policy, graph, master, origin=None if require_full else origin)
    context.require(actual == origin, "scope_changed")
    return actual


def _related_apply(
    tx, action_id: str, policy: context.Policy, graph: context.Graph, master: context.Master
):
    receipt = tx.status(action_id)
    binding = tx.intent_binding(action_id)
    publication = tx.publication(action_id)
    observation = receipt.get("reconciliation_status") if receipt is not None else None
    disk_only = observation == _DISK_PREVIOUS
    context.require(
        receipt is not None
        and binding is not None
        and publication is not None
        and receipt["action"] == "apply"
        and (receipt["status"] == "verified" or observation in {"verified", _DISK_PREVIOUS}),
        "conflict",
    )
    original = _checked_plan(binding["plan_id"], policy.policy_digest)
    _verify_startup(original, policy, graph, master)
    reference = {"action_id": action_id, "policy_digest": policy.policy_digest}
    _receipt_for(reference, binding, receipt, original)
    context.require(
        original.view["action"] == "apply"
        and graph.files[policy.target] == original.candidate
        and graph.identities[policy.target] == publication["disk_identity"]
        and graph.context_sha256(exclude=policy.target)
        == original.private["non_target_context_sha256"]
        and master.sha256 == publication["runtime_sha256"] == original.private["master_sha256"],
        "scope_changed",
    )
    if disk_only:
        context.require(
            ("restore_disk_only" in original.private or tx.staged_identity(action_id) is not None)
            and not tx.activation_pending(action_id),
            "scope_changed",
        )
    data, _, raw_sha = _trusted_backup(original.view["plan_id"], policy)
    context.require(
        raw_sha == original.private["backup_manifest_sha256"]
        and context.digest(data) == original.view["backup_sha256"]
        and context.candidate_for(data, policy) == original.candidate,
        "scope_changed",
    )
    return original, data, raw_sha, disk_only


def _prepare(request: dict) -> dict:
    identifier = request["plan_id"]
    restore = request["op"] == "rollback_prepare"
    action = "restore" if restore else "apply"
    original_id = request.get("original_action_id")
    with _journal().locked() as tx:
        policy = context.active_policy(request["policy_digest"])
        prior = _load_plan(identifier)
        if prior is not None:
            context.require(
                prior.view["policy_digest"] == policy.policy_digest
                and prior.view["action"] == action
                and prior.view["mode_revision"] == request["mode_revision"]
                and prior.view["original_action_id"] == original_id,
                "conflict",
            )
            context.require(
                not prior.retired and datetime.now(UTC) < context.utc(prior.view["expires_at"]),
                "expired",
            )
            return prior.view
        context.require(not tx.has_action(action), "conflict")
        _admit_plan_capacity(tx, identifier, restore=restore)
        start = datetime.now(UTC)
        deadline = min(start + timedelta(minutes=10), policy.expires_at)
        graph = context.capture_graph(policy)
        source = graph.files[policy.target]
        with context.pin_master(policy, graph) as master:
            disk_only = False
            if restore:
                if not isinstance(original_id, str):
                    raise context.Refused("policy_refused")
                original, candidate, backup_manifest_sha, disk_only = _related_apply(
                    tx, original_id, policy, graph, master
                )
                backup_id = original.view["plan_id"]
                backup_sha = context.digest(candidate)
            else:
                startup_sha = runtime.require_started(policy, graph, master)
                candidate = context.candidate_for(source, policy)
                backup_id = identifier
                backup_sha = context.digest(source)
            if restore:
                startup_sha = original.private["startup_sha256"]
            context.require(
                context.probe(policy, candidate=restore and not disk_only), "business_unconfirmed"
            )
            context.syntax_check(policy, graph, candidate)
            if not restore:
                _, backup_manifest_sha = _capture_backup(identifier, policy, graph)
            private = {
                "machine_sha256": snapshot._machine(snapshot.DEFAULT_POLICY),
                "master_sha256": master.sha256,
                "source_identity": graph.identities[policy.target],
                "backup_plan_id": backup_id,
                "backup_manifest_sha256": backup_manifest_sha,
                "non_target_context_sha256": graph.context_sha256(exclude=policy.target),
                "restore_disk_only": disk_only,
                "startup_sha256": startup_sha,
            }
            before, after = (
                (policy.to_port, policy.from_port)
                if restore
                else (policy.from_port, policy.to_port)
            )
            view = {
                "schema_version": 1,
                "status": "ready",
                "plan_id": identifier,
                "action": action,
                "action_id": journal.action_id(identifier, action),
                "policy_digest": policy.policy_digest,
                "mode_revision": request["mode_revision"],
                "source_sha256": context.digest(source),
                "candidate_sha256": context.digest(candidate),
                "backup_sha256": backup_sha,
                "context_sha256": graph.sha256,
                "expires_at": deadline.isoformat(),
                "upstream_before": f"127.0.0.1:{before}",
                "upstream_after": f"127.0.0.1:{after}",
                "affected_site_ids": list(graph.affected_site_ids),
                "syntax": "passed",
                "original_action_id": original_id,
            }
            view["plan_digest"] = _plan_digest(view, private)

            def recheck():
                context.active_policy(policy.policy_digest)
                context.require(start <= datetime.now(UTC) < deadline, "expired")
                context.require(context.capture_graph(policy) == graph, "scope_changed")
                master.verify(policy, graph)
                proof = runtime.require_started(
                    policy, graph, master, origin=startup_sha if restore else None
                )
                context.require(proof == startup_sha, "scope_changed")
                data, _, raw_sha = _trusted_backup(backup_id, policy)
                context.require(
                    context.digest(data) == backup_sha and raw_sha == backup_manifest_sha,
                    "scope_changed",
                )

            snapshot._publish(
                context.PRIVATE_ROOT / "plans" / identifier,
                "candidate.conf",
                candidate,
                {"view": view, "private": private},
                recheck,
                snapshot.DEFAULT_POLICY,
            )
        return view


def _binding_matches(request: dict, plan: Plan) -> bool:
    return all(
        request[key] == plan.view[key]
        for key in ("action_id", "plan_id", "plan_digest", "mode_revision", "policy_digest")
    )


def _before_write(
    plan: Plan, policy: context.Policy, graph: context.Graph, master: context.Master
) -> None:
    context.active_policy(policy.policy_digest)
    context.require(datetime.now(UTC) < context.utc(plan.view["expires_at"]), "expired")
    context.require(
        snapshot._machine(snapshot.DEFAULT_POLICY) == plan.private["machine_sha256"]
        and graph.sha256 == plan.view["context_sha256"]
        and graph.context_sha256(exclude=policy.target) == plan.private["non_target_context_sha256"]
        and graph.identities[policy.target] == plan.private["source_identity"]
        and context.digest(graph.files[policy.target]) == plan.view["source_sha256"]
        and list(graph.affected_site_ids) == plan.view["affected_site_ids"]
        and master.sha256 == plan.private["master_sha256"],
        "scope_changed",
    )
    master.verify(policy, graph)
    _verify_startup(plan, policy, graph, master, require_full=not plan.is_restore)
    backup, manifest, raw_sha = _trusted_backup(plan.private["backup_plan_id"], policy)
    context.require(
        raw_sha == plan.private["backup_manifest_sha256"]
        and context.digest(backup) == plan.view["backup_sha256"],
        "scope_changed",
    )
    if plan.is_restore:
        context.require(
            plan.candidate == backup
            and graph.files[policy.target] == context.candidate_for(backup, policy),
            "scope_changed",
        )
    else:
        context.require(
            backup == graph.files[policy.target]
            and manifest["source_identity"] == graph.identities[policy.target]
            and plan.candidate == context.candidate_for(backup, policy),
            "scope_changed",
        )


def _current_directory(fd: int) -> None:
    with snapshot._directory(context.CONFIG_ROOT / "conf.d", snapshot.DEFAULT_POLICY) as current:
        old, now = os.fstat(fd), os.fstat(current)
    context.require((old.st_dev, old.st_ino) == (now.st_dev, now.st_ino), "scope_changed")


@contextmanager
def _staged(directory: int, data: bytes, identity: dict) -> Generator[tuple[str, tuple[int, int]]]:
    name = ".opsark-nginx-" + secrets.token_hex(16) + ".stage"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    current = os.fstat(fd)
    marker = current.st_dev, current.st_ino
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(fd, identity["uid"], identity["gid"])
            os.fchmod(fd, identity["mode"])
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        yield name, marker
    finally:
        with suppress(FileNotFoundError):
            present = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (present.st_dev, present.st_ino) == marker:
                os.unlink(name, dir_fd=directory)


def _candidate_file(directory: int, name: str, marker: tuple[int, int], plan: Plan) -> dict:
    data, current = snapshot._read(
        directory, name, snapshot.MAX_CONFIG_BYTES, snapshot.DEFAULT_POLICY
    )
    context.require(
        data == plan.candidate
        and (current["dev"], current["ino"]) == marker
        and all(current[k] == plan.private["source_identity"][k] for k in ("uid", "gid", "mode")),
        "scope_changed",
    )
    context.plain_metadata(directory, name, current)
    _current_directory(directory)
    return current


def _after_probe(policy: context.Policy, *, candidate: bool) -> bool:
    deadline = time.monotonic() + 6
    for _ in range(8):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if context.probe(policy, candidate=candidate, seconds=remaining):
            return True
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    return False


def _submit(request: dict, plan: Plan) -> dict:
    context.require(_binding_matches(request, plan), "scope_changed")
    identifier = plan.view["action_id"]
    with _journal().locked() as tx:
        prior = tx.status(identifier)
        if prior is not None:
            binding = tx.intent_binding(identifier)
            assert binding is not None  # noqa: S101 - the checked prior intent exists.
            context.require(binding["approval_id"] == request["approval_id"], "conflict")
            return _receipt_for(request, binding, prior, plan)
        try:
            retired = _retirement_matches(plan)
        except (OSError, ValueError) as error:
            return _action_response(request, "unknown", _reason(error), plan=plan)
        context.require(not retired and not tx.unstarted(identifier), "expired")
        context.require(not tx.has_action(plan.view["action"]), "conflict")
        policy = context.active_policy(request["policy_digest"])
        graph = context.capture_graph(policy)
        with context.pin_master(policy, graph) as master:
            _before_write(plan, policy, graph, master)
            if plan.is_restore:
                original, data, raw_sha, disk_only = _related_apply(
                    tx, plan.view["original_action_id"], policy, graph, master
                )
                context.require(
                    original.view["plan_id"] == plan.private["backup_plan_id"]
                    and data == plan.candidate
                    and raw_sha == plan.private["backup_manifest_sha256"],
                    "scope_changed",
                )
                context.require(disk_only == plan.restore_disk_only, "scope_changed")
            context.require(
                context.probe(policy, candidate=plan.is_restore and not plan.restore_disk_only),
                "business_unconfirmed",
            )
            context.syntax_check(policy, graph, plan.candidate)
            with (
                snapshot._directory(
                    context.CONFIG_ROOT / "conf.d", snapshot.DEFAULT_POLICY
                ) as directory,
                _staged(directory, plan.candidate, plan.private["source_identity"]) as (
                    name,
                    inode,
                ),
            ):
                before = context.capture_graph(policy)
                _before_write(plan, policy, before, master)
                staged = _candidate_file(directory, name, inode, plan)
                tx.begin(
                    plan.view["plan_id"],
                    plan.view["action"],
                    request["approval_id"],
                    plan.view["plan_digest"],
                    plan.view["source_sha256"],
                    plan.view["candidate_sha256"],
                    staged_identity=staged,
                )
                try:
                    _before_write(plan, policy, context.capture_graph(policy), master)
                    context.require(
                        _candidate_file(directory, name, inode, plan) == staged, "scope_changed"
                    )
                    if plan.restore_disk_only:
                        context.require(
                            context.probe(policy, candidate=False), "business_unconfirmed"
                        )
                        _before_write(plan, policy, context.capture_graph(policy), master)
                    data, identity = snapshot._read(
                        directory,
                        policy.target_file,
                        snapshot.MAX_CONFIG_BYTES,
                        snapshot.DEFAULT_POLICY,
                    )
                    context.require(
                        identity == plan.private["source_identity"]
                        and context.digest(data) == plan.view["source_sha256"],
                        "scope_changed",
                    )
                    os.replace(name, policy.target_file, src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                    published = _candidate_file(directory, policy.target_file, inode, plan)
                    post = context.capture_graph(policy)
                    context.require(
                        context.same_context(before, post, policy)
                        and post.identities[policy.target] == published,
                        "scope_changed",
                    )
                    master.verify(policy, post)
                    _verify_startup(plan, policy, post, master)
                    tx.publish(identifier, published, master.sha256)
                    context.active_policy(policy.policy_digest)
                    context.require(
                        datetime.now(UTC) < context.utc(plan.view["expires_at"]), "expired"
                    )
                    if not plan.restore_disk_only:
                        tx.mark_activation(identifier)
                        context.require(context.capture_graph(policy) == post, "scope_changed")
                        master.verify(policy, post)
                        _verify_startup(plan, policy, post, master)
                        context.active_policy(policy.policy_digest)
                        context.require(
                            datetime.now(UTC) < context.utc(plan.view["expires_at"]), "expired"
                        )
                        master.reload()
                    verified = _after_probe(policy, candidate=not plan.is_restore)
                    context.require(context.capture_graph(policy) == post, "scope_changed")
                    master.verify(policy, post)
                    _verify_startup(plan, policy, post, master)
                except Exception:
                    # Intent is durable. Lost/partial execution is never replayed.
                    verified = False
                receipt = tx.finish(identifier, "verified" if verified else "unknown")
                binding = tx.intent_binding(identifier)
                assert binding is not None  # noqa: S101 - original intent was just verified.
                return _receipt_for(request, binding, receipt, plan)


def _observe_unchanged(
    tx: journal._Transaction, plan: Plan, policy: context.Policy, graph: context.Graph
) -> journal.ActionReceipt:
    identifier = plan.view["action_id"]
    source = graph.identities[policy.target]
    context.require(
        not tx.activation_pending(identifier)
        and source == plan.private["source_identity"]
        and context.digest(graph.files[policy.target]) == plan.view["source_sha256"]
        and graph.sha256 == plan.view["context_sha256"]
        and graph.context_sha256(exclude=policy.target) == plan.private["non_target_context_sha256"]
        and list(graph.affected_site_ids) == plan.view["affected_site_ids"]
        and snapshot._machine(snapshot.DEFAULT_POLICY) == plan.private["machine_sha256"],
        "scope_changed",
    )
    with context.pin_master(policy, graph) as master:
        context.require(master.sha256 == plan.private["master_sha256"], "scope_changed")
        _verify_startup(plan, policy, graph, master, require_full=not plan.is_restore)
        context.require(
            context.probe(policy, candidate=plan.is_restore and not plan.restore_disk_only),
            "business_unconfirmed",
        )
        context.require(context.capture_graph(policy) == graph, "scope_changed")
        master.verify(policy, graph)
        _verify_startup(plan, policy, graph, master, require_full=not plan.is_restore)
        return tx.reconcile_unchanged(identifier, source, master.sha256)


def _verify_restore_origin(tx: journal._Transaction, plan: Plan) -> None:
    identifier = plan.view["original_action_id"]
    policy_digest = plan.view["policy_digest"]
    original = _checked_plan(plan.private["backup_plan_id"], policy_digest)
    receipt = tx.status(identifier)
    binding = tx.intent_binding(identifier)
    publication = tx.publication(identifier)
    if receipt is None or binding is None or publication is None:
        raise context.Refused("scope_changed")
    _receipt_for(
        {"action_id": identifier, "policy_digest": policy_digest}, binding, receipt, original
    )
    context.require(
        original.view["action"] == "apply"
        and (receipt["status"] == "verified" or receipt.get("reconciliation_status") == "verified")
        and original.view["source_sha256"] == plan.view["candidate_sha256"]
        and original.view["candidate_sha256"] == plan.view["source_sha256"]
        and original.private["backup_manifest_sha256"] == plan.private["backup_manifest_sha256"]
        and original.private["non_target_context_sha256"]
        == plan.private["non_target_context_sha256"]
        and original.private["startup_sha256"] == plan.private["startup_sha256"]
        and original.private["machine_sha256"]
        == plan.private["machine_sha256"]
        == snapshot._machine(snapshot.DEFAULT_POLICY)
        and publication["disk_identity"] == plan.private["source_identity"]
        and publication["runtime_sha256"] == plan.private["master_sha256"],
        "scope_changed",
    )


def _observe(request: dict) -> dict:
    identifier = request["action_id"]
    with _journal().locked() as tx:
        receipt = tx.status(identifier)
        binding = tx.intent_binding(identifier)
        if receipt is None or binding is None:
            return _action_response(request, "missing", "not_found")
        plan = _checked_plan(binding["plan_id"], request["policy_digest"])
        result = _receipt_for(request, binding, receipt, plan)
        publication = tx.publication(identifier)
        if result["status"] != "unknown" or result["reconciliation_status"] is not None:
            return result
        staged = tx.staged_identity(identifier) if publication is None else None
        if publication is None and staged is None:
            return result
        missing_publication = publication is None or "observed_result_sha256" in publication
        reloaded_restore = plan.is_restore and not plan.restore_disk_only
        try:
            policy = context.active_policy(request["policy_digest"])
            graph = context.capture_graph(policy)
            current = graph.identities[policy.target]
            if publication is None and current == plan.private["source_identity"]:
                observed_receipt = _observe_unchanged(tx, plan, policy, graph)
                return _receipt_for(request, binding, observed_receipt, plan)
            if reloaded_restore:
                if missing_publication or not tx.activation_pending(identifier):
                    return result
                _verify_restore_origin(tx, plan)
            context.require(
                graph.files[policy.target] == plan.candidate
                and (
                    current == publication["disk_identity"]
                    if publication is not None
                    else journal.matches_staged_inode(staged, current)
                )
                and graph.context_sha256(exclude=policy.target)
                == plan.private["non_target_context_sha256"],
                "scope_changed",
            )
            with context.pin_master(policy, graph) as master:
                _verify_startup(plan, policy, graph, master)
                context.require(
                    master.sha256 == plan.private["master_sha256"]
                    and (publication is None or master.sha256 == publication["runtime_sha256"]),
                    "scope_changed",
                )
                observed: journal.Observation = "verified"
                if missing_publication:
                    if tx.activation_pending(identifier) or not context.probe(
                        policy, candidate=False
                    ):
                        return result
                    observed = "verified" if plan.is_restore else _DISK_PREVIOUS
                elif not context.probe(policy, candidate=not plan.is_restore):
                    if (
                        plan.is_restore
                        or "restore_disk_only" not in plan.private
                        or tx.activation_pending(identifier)
                        or not context.probe(policy, candidate=False)
                    ):
                        return result
                    observed = _DISK_PREVIOUS
                context.require(context.capture_graph(policy) == graph, "scope_changed")
                master.verify(policy, graph)
                _verify_startup(plan, policy, graph, master)
                if publication is None:
                    with snapshot._directory(
                        context.CONFIG_ROOT / "conf.d", snapshot.DEFAULT_POLICY
                    ) as directory:
                        marker = current["dev"], current["ino"]
                        context.require(
                            _candidate_file(directory, policy.target_file, marker, plan) == current,
                            "scope_changed",
                        )
                        os.fsync(directory)
                        context.require(context.capture_graph(policy) == graph, "scope_changed")
                        master.verify(policy, graph)
                        _verify_startup(plan, policy, graph, master)
                    tx.observe_publication(identifier, current, master.sha256)
                if reloaded_restore:
                    receipt = tx.reconcile_reloaded_restore(identifier)
                elif plan.is_restore:
                    receipt = tx.reconcile_disk_restore(identifier)
                else:
                    receipt = tx.reconcile(identifier, observed)
                return _receipt_for(request, binding, receipt, plan)
        except (ValueError, OSError, subprocess.SubprocessError):
            return result


def _reason(error: Exception) -> str:
    if (
        type(error) is context.Refused
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in _REASONS
    ):
        return error.args[0]
    if type(error) is journal.JournalError and error.args == (
        "Another action holds the journal lock",
    ):
        return "busy"
    if isinstance(error, FileNotFoundError):
        return "policy_refused"
    return "operation_unconfirmed"


def dispatch(request: dict) -> dict:
    op = request["op"]
    plan = None
    try:
        if op == "plan_status":
            return _checked_plan(request["plan_id"], request["policy_digest"]).view
        if op in {"prepare", "rollback_prepare"}:
            return _prepare(request)
        if op == "status":
            return _historical_status(request)
        if op == "observe":
            return _observe(request)
        plan = _checked_plan(request["plan_id"], request["policy_digest"])
        if op == "reconcile_status":
            return _reconcile_status(request, plan)
        return _submit(request, plan)
    except (
        ValueError,
        TypeError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
        RecursionError,
    ) as error:
        reason = _reason(error)
        if op in {"prepare", "rollback_prepare", "plan_status"}:
            return _plan_error(request, "missing" if reason == "not_found" else "refused", reason)
        if op == "reconcile_status":
            if plan is not None and _binding_matches(request, plan):
                return _action_response(request, "unknown", reason, plan=plan)
            return _action_response(request, "missing", "not_found")
        if op == "submit" and plan is not None and _binding_matches(request, plan):
            try:
                original = _historical_status(request)
                if original["status"] != "missing":
                    return original
            except Exception:
                # A read failure cannot prove that an intent was never written.
                return _action_response(request, "unknown", "operation_unconfirmed", plan=plan)
        return _action_response(request, "refused", reason, plan=plan)


def main() -> int:
    if len(sys.argv) != 1 or sys.stdin.isatty():
        return 126

    def expired(_signal, _frame):
        raise TimeoutError("Nginx action budget exhausted")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(75)
    try:
        request = parse_request(sys.stdin.buffer.read(MAX_WIRE + 1))
        output = context.canonical(dispatch(request)) + b"\n"
        context.require(len(output) <= MAX_WIRE)
        sys.stdout.buffer.write(output)
        return 0
    except Exception:
        sys.stderr.write("Nginx action request refused.\n")
        return 126
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
