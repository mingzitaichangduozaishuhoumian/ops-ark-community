"""One host-owned, assisted-only restart on an explicitly registered full Docker CID."""

import os
import re
import signal
import stat
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

INSTALL = Path("/usr/local/lib/opsark-container-restart")


def installed_directory():
    entry = Path(__file__)
    if entry != INSTALL / "restart_action.py" or entry.resolve(strict=True) != entry:
        raise SystemExit(126)
    for path in (INSTALL, *INSTALL.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit(126)
    for path in (entry, INSTALL / "restart_journal.py", INSTALL / "restart_runtime.py"):
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise SystemExit(126)
    if os.path.lexists(INSTALL / "__pycache__"):
        raise SystemExit(126)
    sys.path.insert(0, str(INSTALL))


if __name__ == "__main__":
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or not sys.flags.isolated
        or not sys.dont_write_bytecode
    ):
        raise SystemExit(126)
    try:
        installed_directory()
    except OSError:
        raise SystemExit(126) from None

if __package__:
    from . import restart_journal as journal
    from . import restart_runtime as runtime
else:
    import restart_journal as journal
    import restart_runtime as runtime

need = runtime.need
digest = runtime.digest
match = runtime.match
integer = runtime.integer
canonical = runtime.canonical
HEX = runtime.HEX
SHORT = re.compile(r"[0-9a-f]{32}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PREFIX = "opsark-container-restart-v1"
STATE = Path("/var/lib/opsark-container-restart")
MAX_INPUT = 4096
MAX_ENTRIES = 1024
POLICY_FIELDS = {
    "schema_version",
    "enabled",
    "mode",
    "mode_revision",
    "expires_at",
    "container_id",
    "image_id",
    "compose_project",
    "compose_service",
}
PLAN_FIELDS = {
    "schema_version",
    "status",
    "policy_digest",
    "plan_id",
    "action_id",
    "mode_revision",
    "plan_digest",
    "container_id",
    "image_id",
    "expires_at",
}
WITNESS = {"daemon", "boot", "created_ns", "started_ns", "pid", "birth", "mounts"}
BINDING = {"plan_id", "plan_digest", "action_id", "mode_revision"}
OPS = {
    "prepare": {"plan_id", "mode_revision"},
    "plan_status": {"plan_id"},
    "submit": BINDING | {"approval_id"},
    "status": {"action_id"},
    "observe": {"action_id"},
    "reconcile_status": BINDING,
}
REASONS = {
    "policy_refused",
    "scope_changed",
    "expired",
    "busy",
    "conflict",
    "not_found",
    "operation_unconfirmed",
}
PENDING = re.compile(r"\.pending-[0-9a-f]{32}\Z")


def now():
    return datetime.now(UTC)


def time_text(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc(value):
    need(match(TIMESTAMP, value), "policy_refused")
    return datetime.fromisoformat(value)


def action_id(plan_id):
    need(match(SHORT, plan_id), "policy_refused")
    return digest({"domain": PREFIX, "plan_id": plan_id})


def exact(value, names, reason="scope_changed"):
    need(type(value) is dict and set(value) == names, reason)


def parse_request(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, "policy_refused")
    value = runtime.decode(raw)
    need(
        type(value) is dict and type(value.get("op")) is str and value["op"] in OPS,
        "policy_refused",
    )
    names = OPS[value["op"]]
    exact(value, {"schema_version", "op", "policy_digest"} | names, "policy_refused")
    need(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and match(HEX, value["policy_digest"]),
        "policy_refused",
    )
    for name in names:
        item = value[name]
        if name == "mode_revision":
            valid = integer(item, 0, 2**53 - 1)
        else:
            valid = match(SHORT if name in {"approval_id", "plan_id"} else HEX, item)
        need(valid, "policy_refused")
    return value


def checked_policy(value):
    exact(value, POLICY_FIELDS, "policy_refused")
    project, service = value["compose_project"], value["compose_service"]
    need(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
        and value["mode"] == "assisted"
        and integer(value["mode_revision"], 0, 2**53 - 1)
        and match(HEX, value["container_id"])
        and match(runtime.IMAGE, value["image_id"])
        and (
            project is None
            and service is None
            or match(PROJECT, project)
            and match(SERVICE, service)
        ),
        "policy_refused",
    )
    utc(value["expires_at"])
    return value


def active_policy(fd, request):
    value = checked_policy(journal.read(fd, "policy.json"))
    need(digest(value) == request["policy_digest"], "scope_changed")
    need(value["mode_revision"] == request["mode_revision"], "scope_changed")
    need(now() < utc(value["expires_at"]), "expired")
    return value


def checked_witness(value):
    exact(value, WITNESS)
    need(
        all(match(HEX, value[key]) for key in ("daemon", "boot", "mounts"))
        and integer(value["created_ns"], 1)
        and integer(value["started_ns"], value["created_ns"])
        and integer(value["pid"], 2, 2**22)
        and integer(value["birth"], 1)
    )
    return value


def plan_hash(view, policy, witness):
    return digest({"domain": PREFIX + "-plan", "view": view, "policy": policy, "before": witness})


def validate_plan(value, identifier):
    exact(value, {"view", "policy", "before"})
    view = value["view"]
    exact(view, PLAN_FIELDS)
    policy = checked_policy(value["policy"])
    before = checked_witness(value["before"])
    need(
        type(view["schema_version"]) is int
        and view["schema_version"] == 1
        and view["status"] == "ready"
        and match(SHORT, view["plan_id"])
        and view["action_id"] == identifier == action_id(view["plan_id"])
        and view["policy_digest"] == digest(policy)
        and all(view[key] == policy[key] for key in ("container_id", "image_id", "mode_revision"))
        and type(view["mode_revision"]) is int
        and utc(view["expires_at"]) <= utc(policy["expires_at"])
    )
    need(
        view["plan_digest"]
        == plan_hash({k: v for k, v in view.items() if k != "plan_digest"}, policy, before)
    )
    return view


def response(request, status, reason=None, view=None, reconciled=None):
    return {
        "schema_version": 1,
        "status": status,
        "policy_digest": request["policy_digest"],
        "action_id": request["action_id"],
        "plan_id": None if view is None else view["plan_id"],
        "plan_digest": None if view is None else view["plan_digest"],
        "mode_revision": None if view is None else view["mode_revision"],
        "reason": reason,
        "reconciliation_status": reconciled,
    }


def plan_error(request, status, reason):
    return {
        "schema_version": 1,
        "status": status,
        "policy_digest": request["policy_digest"],
        "plan_id": request["plan_id"],
        "reason": reason,
    }


def lookup(fd, identifier, *, durable=False):
    # All identifiers are strict hex; each path has exactly one already-validated directory.
    need(match(HEX, identifier))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        child = os.open(identifier, flags, dir_fd=fd)
    except FileNotFoundError:
        return None
    with journal_child(child) as sub:
        if durable:
            os.fsync(sub)
        with os.scandir(sub) as entries:
            for index, entry in enumerate(entries, 1):
                need(
                    index <= 32
                    and (
                        PENDING.fullmatch(entry.name) is not None
                        or entry.name
                        in {
                            "plan.json",
                            "intent.json",
                            "ack.json",
                            "result.json",
                            "observed.json",
                            "not_started.json",
                        }
                    )
                )
        planned = journal.record(sub, "plan.json")
        if planned is None:
            with os.scandir(sub) as entries:
                need(all(PENDING.fullmatch(entry.name) is not None for entry in entries))
            return None
        view = validate_plan(planned, identifier)
        stage = {
            key: journal.record(sub, key + ".json")
            for key in ("intent", "ack", "result", "observed", "not_started")
        }
    expected = view["plan_digest"]
    intent, ack, result, observed, absent = stage.values()
    if absent is not None:
        exact(absent, {"plan_digest"})
        need(
            absent["plan_digest"] == expected
            and all(stage[key] is None for key in ("intent", "ack", "result", "observed"))
        )
    if intent is not None:
        exact(intent, {"plan_digest", "approval_id"})
        need(intent["plan_digest"] == expected and match(SHORT, intent["approval_id"]))
    if ack is not None:
        exact(ack, {"intent_sha256"})
        need(intent is not None and ack["intent_sha256"] == digest(intent))
    if result is not None:
        exact(result, {"intent_sha256", "status", "after"})
        need(
            intent is not None
            and result["intent_sha256"] == digest(intent)
            and result["status"] in {"verified", "unknown"}
        )
        if result["status"] == "verified":
            need(
                ack is not None
                and runtime.changed(planned["before"], checked_witness(result["after"]))
            )
        else:
            need(result["after"] is None)
    if observed is not None:
        exact(observed, {"ack_sha256", "result_sha256", "after"})
        need(
            ack is not None
            and observed["ack_sha256"] == digest(ack)
            and (result is None or result["status"] == "unknown")
            and observed["result_sha256"] == (digest(result) if result is not None else None)
            and runtime.changed(planned["before"], checked_witness(observed["after"]))
        )
    return planned, stage


@contextmanager
def journal_child(fd):
    try:
        info = os.fstat(fd)
        need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
        yield fd
    finally:
        os.close(fd)


def publish(fd, identifier, phase, value, *, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        try:
            os.mkdir(identifier, 0o700, dir_fd=fd)
        except FileExistsError:
            need(lookup(fd, identifier) is None, "conflict")
        os.fsync(fd)
    with journal_child(os.open(identifier, flags, dir_fd=fd)) as sub:
        journal.publish(sub, phase + ".json", value)


def capacity(fd, identifier, *, new=False):
    pending = False
    count = 0
    with os.scandir(fd) as entries:
        for index, entry in enumerate(entries, 1):
            need(index <= MAX_ENTRIES + 1, "busy")
            if entry.name == "policy.json" or PENDING.fullmatch(entry.name):
                continue
            need(match(HEX, entry.name) and entry.is_dir(follow_symlinks=False))
            count += 1
            if entry.name == identifier:
                continue
            existing = lookup(fd, entry.name, durable=True)
            if existing is None:
                continue
            _, stages = existing
            if (
                stages["intent"] is not None
                and stages["observed"] is None
                and (stages["result"] is None or stages["result"]["status"] == "unknown")
            ):
                pending = True
    need(not pending, "conflict")
    need(not new or count < MAX_ENTRIES, "busy")


def ready(fd, request, identifier):
    existing = lookup(fd, identifier, durable=True)
    if existing is not None:
        planned, _stage = existing
        view = planned["view"]
        need(view["policy_digest"] == request["policy_digest"], "scope_changed")
        if request["op"] == "prepare":
            need(view["mode_revision"] == request["mode_revision"], "scope_changed")
            need(now() < utc(view["expires_at"]), "expired")
        return view
    if request["op"] == "plan_status":
        return plan_error(request, "missing", "not_found")
    policy = active_policy(fd, request)
    capacity(fd, identifier, new=True)
    before = checked_witness(runtime.capture(policy))
    active_policy(fd, request)
    expiry = min(now() + timedelta(minutes=5), utc(policy["expires_at"]))
    view = {
        "schema_version": 1,
        "status": "ready",
        "policy_digest": request["policy_digest"],
        "plan_id": request["plan_id"],
        "action_id": identifier,
        "mode_revision": request["mode_revision"],
        "container_id": policy["container_id"],
        "image_id": policy["image_id"],
        "expires_at": time_text(expiry),
    }
    view["plan_digest"] = plan_hash(view, policy, before)
    publish(fd, identifier, "plan", {"view": view, "policy": policy, "before": before}, create=True)
    return view


def history(request, planned, stage):
    view = planned["view"]
    if stage["intent"] is None:
        return response(request, "missing", "not_found")
    result = stage["result"]
    if result is not None and result["status"] == "verified":
        return response(request, "verified", view=view)
    return response(
        request,
        "unknown",
        "operation_unconfirmed",
        view,
        "verified" if stage["observed"] is not None else None,
    )


def submit(fd, request, planned, stage):
    view = planned["view"]
    identifier = view["action_id"]
    if stage["intent"] is not None:
        need(stage["intent"]["approval_id"] == request["approval_id"], "conflict")
        return history(request, planned, stage)
    need(stage["not_started"] is None and now() < utc(view["expires_at"]), "expired")
    capacity(fd, identifier)
    policy = active_policy(fd, request)
    need(runtime.capture(policy) == planned["before"])
    active_policy(fd, request)
    need(now() < utc(view["expires_at"]), "expired")
    intent = {"plan_digest": view["plan_digest"], "approval_id": request["approval_id"]}
    publish(fd, identifier, "intent", intent)
    try:
        active_policy(fd, request)
        need(now() < utc(view["expires_at"]), "expired")
        need(runtime.capture(policy) == planned["before"])
        active_policy(fd, request)
        need(now() < utc(view["expires_at"]), "expired")
        runtime.restart(policy["container_id"])
        publish(fd, identifier, "ack", {"intent_sha256": digest(intent)})
        after = checked_witness(runtime.capture(policy))
        need(runtime.changed(planned["before"], after))
    except (OSError, ValueError, subprocess.SubprocessError):
        publish(
            fd,
            identifier,
            "result",
            {"intent_sha256": digest(intent), "status": "unknown", "after": None},
        )
        return response(request, "unknown", "operation_unconfirmed", view)
    publish(
        fd,
        identifier,
        "result",
        {"intent_sha256": digest(intent), "status": "verified", "after": after},
    )
    return response(request, "verified", view=view)


def observe(fd, request, planned, stage):
    prior = history(request, planned, stage)
    if prior["status"] != "unknown" or stage["ack"] is None or stage["observed"] is not None:
        return prior
    try:
        after = checked_witness(runtime.capture(planned["policy"]))
        need(runtime.changed(planned["before"], after))
    except (OSError, ValueError, subprocess.SubprocessError):
        return prior
    result = stage["result"]
    publish(
        fd,
        planned["view"]["action_id"],
        "observed",
        {
            "ack_sha256": digest(stage["ack"]),
            "result_sha256": digest(result) if result else None,
            "after": after,
        },
    )
    return response(request, "unknown", "operation_unconfirmed", planned["view"], "verified")


def reconcile(fd, request, planned, stage):
    view = planned["view"]
    if stage["intent"] is not None:
        return history(request, planned, stage)
    if stage["not_started"] is None:
        if now() < utc(view["expires_at"]):
            return response(request, "missing", "not_found")
        publish(fd, view["action_id"], "not_started", {"plan_digest": view["plan_digest"]})
    return response(request, "not_started", "expired", view)


def reason_for(error):
    return (
        error.args[0]
        if type(error) is runtime.Refused and len(error.args) == 1 and (error.args[0] in REASONS)
        else "operation_unconfirmed"
    )


def dispatch(request):
    op = request["op"]
    is_plan = op in {"prepare", "plan_status"}
    identifier = action_id(request["plan_id"]) if is_plan else request["action_id"]
    view = None
    try:
        # Stable snapshots and fsync prevent a visible-but-uncommitted receipt from
        # becoming terminal to the caller after a failed publisher.
        with journal.directory(STATE, locked=True) as fd:
            if is_plan:
                return ready(fd, request, identifier)
            existing = lookup(fd, identifier, durable=True)
            if existing is None:
                return response(request, "missing", "not_found")
            planned, stage = existing
            candidate = planned["view"]
            need(candidate["policy_digest"] == request["policy_digest"], "scope_changed")
            if op in {"submit", "reconcile_status"}:
                need(all(request[key] == candidate[key] for key in BINDING), "scope_changed")
            view = candidate
            if op == "status":
                return history(request, planned, stage)
            if op == "observe":
                return observe(fd, request, planned, stage)
            if op == "reconcile_status":
                return reconcile(fd, request, planned, stage)
            return submit(fd, request, planned, stage)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        reason = reason_for(error)
        if is_plan:
            return plan_error(request, "refused", reason)
        if (
            op == "submit"
            and view is not None
            and reason in {"expired", "scope_changed", "conflict", "policy_refused"}
        ):
            return response(request, "refused", reason, view)
        return response(request, "unknown", reason, view)


def main():
    if len(sys.argv) != 1 or sys.stdin.isatty() or sys.platform != "linux" or os.geteuid() != 0:
        return 126

    def timeout(_signal, _frame):
        raise TimeoutError("request deadline")

    os.umask(0o077)
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(75)
    try:
        request = parse_request(sys.stdin.buffer.read(MAX_INPUT + 1))
        result = canonical(dispatch(request)) + b"\n"
        need(len(result) <= MAX_INPUT)
        sys.stdout.buffer.write(result)
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return 126
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
