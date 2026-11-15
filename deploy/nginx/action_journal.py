"""Keep durable, single-use intents and receipts for trusted local Nginx actions."""

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

if sys.platform == "linux":
    import fcntl

_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_NAME = re.compile(
    r"([0-9a-f]{64})\."
    r"(intent|publication|observed_publication|activation|result|reconciliation|not_started)\.json\Z"
)
_ACTIONS = ("apply", "restore")
_MAX_RECORD = 4096
_MAX_ENTRIES = 256
_DISK_FIELDS = {"dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid"}

type Outcome = Literal["verified", "unknown"]
type Observation = Literal["verified", "disk_published_live_previous", "unchanged_from_preview"]
UNCHANGED_FROM_PREVIEW: Literal["unchanged_from_preview"] = "unchanged_from_preview"


class JournalError(ValueError):
    """A local journal operation could not establish the required safety checks."""


class ActionReceipt(TypedDict):
    schema_version: Literal[1]
    action_id: str
    action: str
    status: Outcome
    source_sha256: str
    candidate_sha256: str
    reconciliation_status: NotRequired[Observation]


class _Evidence(TypedDict):
    intent: dict
    publication: dict | None
    observed_publication: dict | None
    activation: dict | None
    result: dict | None
    reconciliation: dict | None


def _valid(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def action_id(plan_id: str, action: str = "apply") -> str:
    """Derive the same ID across approvals of the same plan and action."""
    if not _valid(_ID, plan_id) or action not in _ACTIONS:
        raise JournalError("Invalid action identity")
    return _digest({"domain": "opsark-nginx-action-v1", "plan_id": plan_id, "action": action})


@contextmanager
def _directory(directory: Path, *, durable: bool = False) -> Generator[int]:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise JournalError("The action journal requires the trusted Linux administrator")
    if directory.anchor != "/" or ".." in directory.parts or directory == Path("/"):
        raise JournalError("The action journal needs an absolute private directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open("/", flags)
        try:
            for part in directory.parts[1:]:
                info = os.fstat(fd)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise JournalError("Untrusted action journal parent")
                # A newly provisioned directory entry must also survive power loss.
                if durable:
                    os.fsync(fd)
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o077:
                raise JournalError("Action journal directory is not private")
            yield fd
        finally:
            os.close(fd)
    except OSError:
        raise JournalError("Action journal is unavailable") from None


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _record(fd: int, name: str, seal: str) -> dict | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME
    try:
        item = os.open(name, flags, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(item, "rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & 0o7077
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_RECORD
        ):
            raise JournalError("Untrusted action journal record")
        data = handle.read(_MAX_RECORD + 1)
        after = os.fstat(handle.fileno())
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if (
        len(data) != before.st_size
        or _identity(before) != _identity(after)
        or _identity(before) != _identity(current)
    ):
        raise JournalError("Action journal record changed while reading")
    try:
        value = json.loads(data)
        if not isinstance(value, dict) or data != _canonical(value) + b"\n":
            raise JournalError("Invalid canonical action journal record")
        declared = value.pop(seal)
        if declared != _digest(value):
            raise JournalError("Action journal seal did not match")
    except (ValueError, KeyError, TypeError, RecursionError):
        raise JournalError("Invalid action journal record") from None
    return {**value, seal: declared}


def _publish(fd: int, name: str, value: dict, seal: str) -> None:
    pending = ".pending-" + secrets.token_hex(16)
    payload = _canonical({**value, seal: _digest(value)}) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    item = os.open(pending, flags, 0o600, dir_fd=fd)
    try:
        with os.fdopen(item, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Cooperating writers hold the same directory lock, including this check and rename.
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise JournalError("Action journal record already exists")
        os.rename(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(pending, dir_fd=fd)


def _version(value: dict) -> bool:
    return type(value["schema_version"]) is int and value["schema_version"] == 1


def _valid_disk_identity(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _DISK_FIELDS
        and all(type(item) is int and 0 <= item < 2**64 for item in value.values())
        and value["ino"] > 0
        and 0 < value["size"] <= 262_144
        and value["uid"] == 0
        and value["gid"] < 2**32
        and value["mode"] <= 0o7777
        and not value["mode"] & 0o7022
    )


def matches_staged_inode(staged: object, current: object) -> bool:
    """Compare the stable fields of the original staged inode across its rename."""
    return (
        isinstance(staged, dict)
        and isinstance(current, dict)
        and _valid_disk_identity(staged)
        and _valid_disk_identity(current)
        and current["ctime_ns"] >= staged["ctime_ns"]
        and all(staged[key] == current[key] for key in _DISK_FIELDS - {"ctime_ns"})
    )


def _separate_from_stage(staged: dict | None, current: dict) -> bool:
    return (
        staged is not None
        and _valid_disk_identity(staged)
        and _valid_disk_identity(current)
        and (staged["dev"], staged["ino"]) != (current["dev"], current["ino"])
    )


def _not_started(fd: int, identifier: str) -> dict | None:
    if not _valid(_SHA256, identifier):
        raise JournalError("Invalid action identity")
    record = _record(fd, identifier + ".not_started.json", "not_started_sha256")
    if record is not None and (
        set(record)
        != {"schema_version", "action_id", "action", "plan_id", "plan_sha256", "not_started_sha256"}
        or not _version(record)
        or record["action_id"] != identifier
        or action_id(record["plan_id"], record["action"]) != identifier
        or not _valid(_SHA256, record["plan_sha256"])
    ):
        raise JournalError("Invalid action journal no-start record")
    return record


def _lookup(fd: int, identifier: str) -> _Evidence | None:
    if not _valid(_SHA256, identifier):
        raise JournalError("Invalid action identity")
    # Observe dependent records first so lock-free readers never miss a predecessor
    # that a cooperating writer durably published before its dependent.
    reconciliation = _record(fd, identifier + ".reconciliation.json", "reconciliation_sha256")
    observed_publication = _record(
        fd, identifier + ".observed_publication.json", "publication_sha256"
    )
    result = _record(fd, identifier + ".result.json", "result_sha256")
    activation = _record(fd, identifier + ".activation.json", "activation_sha256")
    publication = _record(fd, identifier + ".publication.json", "publication_sha256")
    intent = _record(fd, identifier + ".intent.json", "intent_sha256")
    if intent is None:
        if all(
            record is None
            for record in (publication, observed_publication, activation, result, reconciliation)
        ):
            return None
        raise JournalError("Action journal evidence is missing its intent")
    has_stage = "staged_identity" in intent
    if (
        set(intent) - {"staged_identity"}
        != {
            "schema_version",
            "action_id",
            "action",
            "plan_id",
            "approval_id",
            "plan_sha256",
            "source_sha256",
            "candidate_sha256",
            "intent_sha256",
        }
        or not _version(intent)
        or intent["action_id"] != identifier
        or action_id(intent["plan_id"], intent["action"]) != identifier
        or not _valid(_ID, intent["approval_id"])
        or not all(
            _valid(_SHA256, intent[field])
            for field in ("plan_sha256", "source_sha256", "candidate_sha256")
        )
        or intent["source_sha256"] == intent["candidate_sha256"]
        or _not_started(fd, identifier) is not None
        or (has_stage and not _valid_disk_identity(intent["staged_identity"]))
    ):
        raise JournalError("Invalid action journal intent")
    if publication is not None and (
        set(publication)
        != {
            "schema_version",
            "action_id",
            "intent_sha256",
            "disk_identity",
            "runtime_sha256",
            "publication_sha256",
        }
        or not _version(publication)
        or publication["action_id"] != identifier
        or publication["intent_sha256"] != intent["intent_sha256"]
        or not _valid_disk_identity(publication["disk_identity"])
        or not _valid(_SHA256, publication["runtime_sha256"])
        or (
            has_stage
            and not matches_staged_inode(intent["staged_identity"], publication["disk_identity"])
        )
    ):
        raise JournalError("Action journal publication did not match its intent")
    if activation is not None and (
        set(activation)
        != {"schema_version", "action_id", "publication_sha256", "activation_sha256"}
        or not _version(activation)
        or activation["action_id"] != identifier
        or publication is None
        or activation["publication_sha256"] != publication["publication_sha256"]
    ):
        raise JournalError("Action journal activation did not match its publication")
    if result is not None:
        fields = {"schema_version", "action_id", "intent_sha256", "status", "result_sha256"}
        if publication is not None:
            fields.add("publication_sha256")
        if (
            set(result) != fields
            or not _version(result)
            or result["action_id"] != identifier
            or result["intent_sha256"] != intent["intent_sha256"]
            or result["status"] not in ("verified", "unknown")
            or (
                publication is not None
                and result["publication_sha256"] != publication["publication_sha256"]
            )
        ):
            raise JournalError("Action journal result did not match its predecessors")
    if observed_publication is not None and (
        set(observed_publication)
        != {
            "schema_version",
            "action_id",
            "intent_sha256",
            "disk_identity",
            "runtime_sha256",
            "observed_result_sha256",
            "publication_sha256",
        }
        or not _version(observed_publication)
        or observed_publication["action_id"] != identifier
        or observed_publication["intent_sha256"] != intent["intent_sha256"]
        or publication is not None
        or activation is not None
        or not matches_staged_inode(
            intent.get("staged_identity"), observed_publication["disk_identity"]
        )
        or not _valid(_SHA256, observed_publication["runtime_sha256"])
        or (result is not None and result["status"] != "unknown")
        or observed_publication["observed_result_sha256"]
        != (result["result_sha256"] if result is not None else None)
    ):
        raise JournalError("Observed publication did not match the interrupted action")
    effective_publication = publication or observed_publication
    if reconciliation is not None:
        fields = {
            "schema_version",
            "action_id",
            "intent_sha256",
            "publication_sha256",
            "result_sha256",
            "status",
            "reconciliation_sha256",
        }
        is_restore = intent["action"] == "restore"
        observation = reconciliation.get("status")
        reloaded_restore = "activation_sha256" in reconciliation
        if is_restore:
            fields.add("action")
        if reloaded_restore:
            fields.add("activation_sha256")
        if observation == UNCHANGED_FROM_PREVIEW:
            fields.update(("disk_identity", "runtime_sha256"))
        if (
            set(reconciliation) != fields
            or not _version(reconciliation)
            or reconciliation["action_id"] != identifier
            or reconciliation["intent_sha256"] != intent["intent_sha256"]
            or (result is not None and result["status"] != "unknown")
            or reconciliation["result_sha256"]
            != (result["result_sha256"] if result is not None else None)
            or (is_restore and reconciliation["action"] != "restore")
            or (
                reloaded_restore
                and (
                    not is_restore
                    or observation != "verified"
                    or publication is None
                    or activation is None
                    or reconciliation["activation_sha256"] != activation["activation_sha256"]
                )
            )
        ):
            raise JournalError("Action journal reconciliation did not match its predecessors")
        if observation == UNCHANGED_FROM_PREVIEW:
            if (
                effective_publication is not None
                or activation is not None
                or reconciliation["publication_sha256"] is not None
                or not _separate_from_stage(
                    intent.get("staged_identity"), reconciliation["disk_identity"]
                )
                or not _valid(_SHA256, reconciliation["runtime_sha256"])
            ):
                raise JournalError("Unchanged observation did not match the staged intent")
        elif (
            effective_publication is None
            or reconciliation["publication_sha256"] != effective_publication["publication_sha256"]
            or observation not in ("verified", "disk_published_live_previous")
            or (is_restore and observation != "verified")
            or (
                activation is not None
                and (
                    (is_restore and not reloaded_restore)
                    or observation == "disk_published_live_previous"
                )
            )
            or (
                observed_publication is not None
                and not is_restore
                and observation != "disk_published_live_previous"
            )
        ):
            raise JournalError("Action journal reconciliation did not match its predecessors")
    return {
        "intent": intent,
        "publication": publication,
        "observed_publication": observed_publication,
        "activation": activation,
        "result": result,
        "reconciliation": reconciliation,
    }


def _receipt(
    intent: dict, outcome: Outcome, *, reconciled: Observation | None = None
) -> ActionReceipt:
    receipt: ActionReceipt = {
        "schema_version": 1,
        "action_id": intent["action_id"],
        "action": intent["action"],
        "status": outcome,
        "source_sha256": intent["source_sha256"],
        "candidate_sha256": intent["candidate_sha256"],
    }
    if reconciled is not None:
        receipt["reconciliation_status"] = reconciled
    return receipt


def _current_receipt(evidence: _Evidence | None) -> ActionReceipt | None:
    if evidence is None:
        return None
    result = evidence["result"]
    observation = evidence["reconciliation"]
    return _receipt(
        evidence["intent"],
        result["status"] if result is not None else "unknown",
        reconciled=observation["status"] if observation is not None else None,
    )


class _Transaction:
    def __init__(self, fd: int):
        self._fd: int | None = fd
        self._started: set[str] = set()

    def _descriptor(self) -> int:
        if self._fd is None:
            raise JournalError("Action journal lock is closed")
        return self._fd

    def status(self, identifier: str) -> ActionReceipt | None:
        return _current_receipt(_lookup(self._descriptor(), identifier))

    def intent_binding(self, identifier: str) -> dict | None:
        """Return trusted private binding fields for a related operator action."""
        evidence = _lookup(self._descriptor(), identifier)
        if evidence is None:
            return None
        return {
            field: evidence["intent"][field]
            for field in (
                "plan_id",
                "approval_id",
                "plan_sha256",
                "action",
                "source_sha256",
                "candidate_sha256",
            )
        }

    def publication(self, identifier: str) -> dict | None:
        """Read the bound private disk and runtime evidence for a known action."""
        evidence = _lookup(self._descriptor(), identifier)
        return (evidence["publication"] or evidence["observed_publication"]) if evidence else None

    def staged_identity(self, identifier: str) -> dict | None:
        evidence = _lookup(self._descriptor(), identifier)
        return evidence["intent"].get("staged_identity") if evidence else None

    def activation_pending(self, identifier: str) -> bool:
        """Determine whether an activation could already have been signalled."""
        evidence = _lookup(self._descriptor(), identifier)
        if evidence is None:
            raise JournalError("Activation status needs an original intent")
        return evidence["activation"] is not None

    def has_action(self, action: str) -> bool:
        """Check a workspace-wide single-action gate without trusting damaged records."""
        if action not in _ACTIONS:
            raise JournalError("Invalid journal action")
        fd = self._descriptor()
        names: dict[str, set[str]] = {}
        # Keep the locked directory's seek position independent of repeated scans.
        scan_fd = os.open(
            ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOATIME, dir_fd=fd
        )
        try:
            with os.scandir(scan_fd) as records:
                for count, entry in enumerate(records, start=1):
                    if count > _MAX_ENTRIES:
                        raise JournalError("Action journal exceeds the inspection budget")
                    match = _RECORD_NAME.fullmatch(entry.name)
                    if match is None:
                        raise JournalError("Unexpected action journal entry")
                    identifier, role = match.groups()
                    names.setdefault(identifier, set()).add(role)
        finally:
            os.close(scan_fd)
        found = False
        for identifier, roles in names.items():
            if roles == {"not_started"} and _not_started(fd, identifier) is not None:
                continue
            evidence = _lookup(fd, identifier)
            if evidence is None or roles != {
                role for role, record in evidence.items() if record is not None
            }:
                raise JournalError("Action journal entries changed during inspection")
            if evidence["intent"]["action"] != action:
                continue
            observed = evidence["reconciliation"]
            if observed is not None and observed["status"] == UNCHANGED_FROM_PREVIEW:
                # A visible record may have been renamed just before an interrupted fsync.
                os.fsync(fd)
                continue
            found = True
        return found

    def close_unstarted(self, plan_id: str, action: str, plan_sha256: str) -> None:
        """Permanently close an expired identity with no original action intent."""
        fd = self._descriptor()
        identifier = action_id(plan_id, action)
        if not _valid(_SHA256, plan_sha256) or self.status(identifier) is not None:
            raise JournalError("No-start closure requires an unused plan identity")
        record = {
            "schema_version": 1,
            "action_id": identifier,
            "action": action,
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
        }
        prior = _not_started(fd, identifier)
        if prior is None:
            _publish(fd, identifier + ".not_started.json", record, "not_started_sha256")
        elif prior == {**record, "not_started_sha256": _digest(record)}:
            # A prior interrupted publisher may have renamed the file before fsync.
            os.fsync(fd)
        else:
            raise JournalError("No-start closure did not match the original plan")

    def unstarted(self, identifier: str) -> bool:
        return _not_started(self._descriptor(), identifier) is not None

    def begin(
        self,
        plan_id: str,
        action: str,
        approval_id: str,
        plan_sha256: str,
        source_sha256: str,
        candidate_sha256: str,
        *,
        staged_identity: dict | None = None,
    ) -> ActionReceipt:
        """Consume one plan/action and fsync its intent before any side effect."""
        fd = self._descriptor()
        identifier = action_id(plan_id, action)
        if (
            not _valid(_ID, approval_id)
            or not all(_valid(_SHA256, v) for v in (plan_sha256, source_sha256, candidate_sha256))
            or source_sha256 == candidate_sha256
            or (staged_identity is not None and not _valid_disk_identity(staged_identity))
        ):
            raise JournalError("Invalid action journal binding")
        if self.status(identifier) is not None or _not_started(fd, identifier) is not None:
            raise JournalError("This action already has a durable intent")
        intent = {
            "schema_version": 1,
            "action_id": identifier,
            "action": action,
            "plan_id": plan_id,
            "approval_id": approval_id,
            "plan_sha256": plan_sha256,
            "source_sha256": source_sha256,
            "candidate_sha256": candidate_sha256,
        }
        if staged_identity is not None:
            intent["staged_identity"] = dict(staged_identity)
        _publish(fd, identifier + ".intent.json", intent, "intent_sha256")
        self._started.add(identifier)
        return _receipt(intent, "unknown")

    def publish(self, identifier: str, disk_identity: dict[str, int], runtime_sha256: str) -> dict:
        """Fsync exact disk/runtime evidence before notifying the service."""
        fd = self._descriptor()
        if (
            identifier not in self._started
            or not _valid_disk_identity(disk_identity)
            or not _valid(_SHA256, runtime_sha256)
        ):
            raise JournalError("Publication needs an original locked intent and valid evidence")
        evidence = _lookup(fd, identifier)
        if (
            evidence is None
            or any(
                evidence[role] is not None for role in ("publication", "result", "reconciliation")
            )
            or (
                "staged_identity" in evidence["intent"]
                and not matches_staged_inode(evidence["intent"]["staged_identity"], disk_identity)
            )
        ):
            raise JournalError("Action publication cannot replace existing evidence")
        publication = {
            "schema_version": 1,
            "action_id": identifier,
            "intent_sha256": evidence["intent"]["intent_sha256"],
            "disk_identity": dict(disk_identity),
            "runtime_sha256": runtime_sha256,
        }
        _publish(fd, identifier + ".publication.json", publication, "publication_sha256")
        return {**publication, "publication_sha256": _digest(publication)}

    def observe_publication(
        self, identifier: str, disk_identity: dict, runtime_sha256: str
    ) -> None:
        """Seal independently observed disk publication without changing its historical result."""
        fd = self._descriptor()
        evidence = _lookup(fd, identifier)
        if (
            evidence is None
            or identifier in self._started
            or any(
                evidence[role] is not None
                for role in ("publication", "observed_publication", "activation", "reconciliation")
            )
            or not matches_staged_inode(evidence["intent"].get("staged_identity"), disk_identity)
            or not _valid(_SHA256, runtime_sha256)
            or (evidence["result"] is not None and evidence["result"]["status"] != "unknown")
        ):
            raise JournalError(
                "Publication observation needs the original interrupted staged inode"
            )
        result = evidence["result"]
        publication = {
            "schema_version": 1,
            "action_id": identifier,
            "intent_sha256": evidence["intent"]["intent_sha256"],
            "disk_identity": dict(disk_identity),
            "runtime_sha256": runtime_sha256,
            "observed_result_sha256": result["result_sha256"] if result is not None else None,
        }
        _publish(fd, identifier + ".observed_publication.json", publication, "publication_sha256")

    def mark_activation(self, identifier: str) -> None:
        """Record that this transaction may signal the pinned service next."""
        fd = self._descriptor()
        evidence = _lookup(fd, identifier)
        if (
            identifier not in self._started
            or evidence is None
            or evidence["publication"] is None
            or any(
                evidence[role] is not None for role in ("activation", "result", "reconciliation")
            )
        ):
            raise JournalError("Activation requires the original durable publication")
        activation = {
            "schema_version": 1,
            "action_id": identifier,
            "publication_sha256": evidence["publication"]["publication_sha256"],
        }
        _publish(fd, identifier + ".activation.json", activation, "activation_sha256")

    def finish(self, identifier: str, outcome: Outcome) -> ActionReceipt:
        """Seal a result only in the transaction that published its intent."""
        fd = self._descriptor()
        if outcome not in ("verified", "unknown") or identifier not in self._started:
            raise JournalError("Action result is outside its original locked transaction")
        evidence = _lookup(fd, identifier)
        if (
            evidence is None
            or evidence["result"] is not None
            or evidence["reconciliation"] is not None
        ):
            raise JournalError("Action result cannot replace existing evidence")
        intent = evidence["intent"]
        result = {
            "schema_version": 1,
            "action_id": identifier,
            "intent_sha256": intent["intent_sha256"],
            "status": outcome,
        }
        if evidence["publication"] is not None:
            result["publication_sha256"] = evidence["publication"]["publication_sha256"]
        _publish(fd, identifier + ".result.json", result, "result_sha256")
        self._started.remove(identifier)
        return _receipt(intent, outcome)

    def reconcile(self, identifier: str, observed: Observation = "verified") -> ActionReceipt:
        """Seal an independent observation after the caller proves an unknown apply."""
        return self._reconcile(identifier, observed, "apply")

    def reconcile_disk_restore(self, identifier: str) -> ActionReceipt:
        """Seal proof of a disk restore that did not try to activate the service."""
        return self._reconcile(identifier, "verified", "restore")

    def reconcile_reloaded_restore(self, identifier: str) -> ActionReceipt:
        """Seal independently verified live restore evidence against the activation marker."""
        return self._reconcile(identifier, "verified", "restore", reloaded_restore=True)

    def reconcile_unchanged(
        self, identifier: str, source_identity: dict, runtime_sha256: str
    ) -> ActionReceipt:
        """Seal exact prior disk/runtime evidence and free only this action's slot."""
        fd = self._descriptor()
        evidence = _lookup(fd, identifier)
        if evidence is None or identifier in self._started:
            raise JournalError("Unchanged observation requires a prior staged intent")
        intent, result = evidence["intent"], evidence["result"]
        if (
            any(
                evidence[key] is not None
                for key in ("publication", "observed_publication", "activation")
            )
            or (result is not None and result["status"] != "unknown")
            or not _separate_from_stage(intent.get("staged_identity"), source_identity)
            or not _valid(_SHA256, runtime_sha256)
        ):
            raise JournalError("Unchanged observation requires an unpublished staged action")
        record = {
            "schema_version": 1,
            "action_id": identifier,
            "intent_sha256": intent["intent_sha256"],
            "publication_sha256": None,
            "result_sha256": result["result_sha256"] if result is not None else None,
            "status": UNCHANGED_FROM_PREVIEW,
            "disk_identity": dict(source_identity),
            "runtime_sha256": runtime_sha256,
        }
        if intent["action"] == "restore":
            record["action"] = "restore"
        existing = evidence["reconciliation"]
        if existing is None:
            _publish(fd, identifier + ".reconciliation.json", record, "reconciliation_sha256")
        elif existing == {**record, "reconciliation_sha256": _digest(record)}:
            os.fsync(fd)
        else:
            raise JournalError("Unchanged observation differs from the original evidence")
        return _receipt(intent, "unknown", reconciled=UNCHANGED_FROM_PREVIEW)

    def _reconcile(
        self, identifier: str, observed: Observation, action: str, *, reloaded_restore: bool = False
    ) -> ActionReceipt:
        fd = self._descriptor()
        evidence = _lookup(fd, identifier)
        if evidence is None or identifier in self._started:
            raise JournalError("Reconciliation requires a prior unknown action")
        intent, publication, result = (
            evidence["intent"],
            evidence["publication"] or evidence["observed_publication"],
            evidence["result"],
        )
        activation = evidence["activation"]
        if (
            intent["action"] != action
            or publication is None
            or (result is not None and result["status"] != "unknown")
            or observed not in {"verified", "disk_published_live_previous"}
            or (
                evidence["observed_publication"] is not None
                and action == "apply"
                and observed != "disk_published_live_previous"
            )
            or (
                activation is not None
                and (
                    (action == "restore" and not reloaded_restore)
                    or observed == "disk_published_live_previous"
                )
            )
            or (
                reloaded_restore
                and (
                    action != "restore"
                    or observed != "verified"
                    or evidence["publication"] is None
                    or activation is None
                )
            )
        ):
            raise JournalError("Reconciliation requires an unknown action with a publication")
        if evidence["reconciliation"] is None:
            reconciliation = {
                "schema_version": 1,
                "action_id": identifier,
                "intent_sha256": intent["intent_sha256"],
                "publication_sha256": publication["publication_sha256"],
                "result_sha256": result["result_sha256"] if result is not None else None,
                "status": observed,
            }
            if action == "restore":
                reconciliation["action"] = action
            if reloaded_restore and activation is not None:
                reconciliation["activation_sha256"] = activation["activation_sha256"]
            _publish(
                fd, identifier + ".reconciliation.json", reconciliation, "reconciliation_sha256"
            )
        else:
            observed = evidence["reconciliation"]["status"]
            os.fsync(fd)
        return _receipt(intent, "unknown", reconciled=observed)


class ActionJournal:
    """Use one fixed precreated private directory for a managed fixture."""

    def __init__(self, directory: Path):
        self._path = directory

    def status(self, identifier: str) -> ActionReceipt | None:
        with _directory(self._path) as fd:
            return _current_receipt(_lookup(fd, identifier))

    @contextmanager
    def locked(self) -> Generator[_Transaction]:
        with _directory(self._path, durable=True) as fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise JournalError("Another action holds the journal lock") from None
            transaction = _Transaction(fd)
            try:
                yield transaction
            finally:
                transaction._fd = None
                # Closing the directory descriptor releases the advisory lock.
