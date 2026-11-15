"""One native readonly-SSH restart between direct ACK and original-task query.

The frozen session browser still owns UI, real processes and reconciliation.
This adapter only inserts one explicitly supplied, independently verified lab
lifecycle operation. It never initializes, grants, provisions or selects a host.
"""

from __future__ import annotations

import hashlib
import inspect
import re
from pathlib import Path
from threading import Lock
from unittest.mock import patch

import browser_defense_session_native_smoke as session
from defense_abrupt_process import immutable_submission
from defense_recheck_process_restart import RestartAcceptanceError, _json, require

from opsark.config import Settings

SESSION_DRIVER_SHA256 = "c669e28911f01c33de72dad92fc8bb59409664fb10ed321a651298c7ca2b13ac"
SESSION_RUN_SHA256 = "a8ebc1dd7142eecc93bb93ee5b35091ed8269d6db38fd96be29bbb44997f60f8"
SESSION_RESTART_SHA256 = "98c26a1f36b2be832bd654375b1c33305599f348044cd5662d020b3dce2ac2cb"
RESTART_PARAMETERS = (
    "browser",
    "process",
    "settings",
    "session_path",
    "host_id",
    "reference",
    "cursor",
    "rid",
    "final",
    "ledger",
    "immutable",
    "directory",
    "record",
)
_LOCK = Lock()
_ORIGINAL_RESTART = session._restart
_ORIGINAL_RUN = session.run_session_browser
HEX = re.compile(r"[0-9a-f]{64}\Z")
PRESERVED = (
    "protected_process_sha256",
    "protected_listener_sha256",
    "netns_sha256",
    "protected_log_identity_sha256",
    "protected_log_sha256",
    "public_pin_sha256",
    "key_file_identity_sha256",
    "protected_config_sha256",
    "transport_config_sha256",
    "roles_policy_sha256",
    "authority_sha256",
    "root_ledger_sha256",
    "root_grants_sha256",
    "root_usage_sha256",
    "root_intents_sha256",
    "root_binding_sha256",
)
REPLACED = ("transport_process_sha256", "transport_listener_sha256")
RESTART_FLAGS = (
    "old_transport_terminated",
    "new_transport_started",
    "transport_identity_changed",
    "transport_listening",
    "no_inflight_transport_sessions",
    "protected_listener_preserved",
    "immutable_state_preserved",
)
ZERO_COUNTS = (
    "initialize_calls_during_restart",
    "provision_calls_during_restart",
    "nft_initialize_calls_during_restart",
    "host_key_generation_calls_during_restart",
)
ONE_COUNTS = (
    "usage_count_before",
    "usage_count_after",
    "intent_count_before",
    "intent_count_after",
)


def _verified_source():
    path = Path(session.__file__).resolve()
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == SESSION_DRIVER_SHA256,
        "transport_session_source_changed",
    )
    for function, name, expected in (
        (session.run_session_browser, "run_session_browser", SESSION_RUN_SHA256),
        (session._restart, "_restart", SESSION_RESTART_SHA256),
    ):
        require(
            function is (_ORIGINAL_RESTART if name == "_restart" else _ORIGINAL_RUN)
            and function.__module__ == session.__name__
            and function.__qualname__ == name
            and function.__globals__ is session.__dict__
            and Path(function.__code__.co_filename).resolve() == path
            and hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == expected,
            "transport_session_function_changed",
        )
    require(
        tuple(inspect.signature(_ORIGINAL_RESTART).parameters) == RESTART_PARAMETERS,
        "transport_restart_signature_changed",
    )


class _Once:
    def __init__(self):
        self.calls = 0

    def take(self):
        require(self.calls == 0, "transport_restart_repeated")
        self.calls += 1


def _require_callback(callback):
    require(
        callable(callback) and not inspect.iscoroutinefunction(callback),
        "transport_restart_callback_required",
    )


def _before_restart(bound):
    record, ledger = bound["record"], bound["ledger"]
    require(
        record.get("controller_process_restart_verified") is True
        and record.get("phase") == "restart_readonly"
        and record.get("terminal_phase") == "completed"
        and record.get("expected_ack_behavior") == "direct_ack"
        and record.get("expected_ai_calls") == 0
        and record.get("business_verdict") == "pending"
        and record.get("business_recollection") is False
        and len(record.get("processes", [])) == 1,
        "transport_restart_wrong_boundary",
    )
    first = record["processes"][0]
    require(
        first.get("stopped") is True
        and first.get("session_worker_stopped") is True
        and first.get("worker_disabled") is True
        and first.get("model_attempts") == 0
        and first.get("write_requests") == {"mode": 1, "arm": 1, "session_start": 1},
        "transport_first_process_not_stopped",
    )
    require(
        bound["process"].index == 2
        and bound["final"]["phase"] == bound["final"]["effective_phase"] == "completed"
        and bound["final"]["action_request_id"] == bound["rid"]
        and bound["final"]["cursor_request_id"] == bound["cursor"]
        and ledger["totals"]
        == {"sessions": 1, "actions": 1, "apply_intents": 1, "business_rechecks": 0}
        and ledger["fees"] == [{"kind": "execution", "state": "consumed", "count": 1}]
        and ledger["ai_evidence"] is None,
        "transport_original_action_not_single_rule_ack",
    )
    apply = [row for row in ledger["requests"] if row["op"] == "apply"]
    require(
        len(apply) == 1
        and apply[0]["dispatch_phase"] == "replied"
        and HEX.fullmatch(apply[0]["reply_sha256"] or "") is not None,
        "transport_direct_apply_receipt_missing",
    )
    require(
        sum(
            row["op"] == "apply" and row["accepted"] == 1 and row["state"] == "active"
            for row in ledger["observations"]
        )
        == 1,
        "transport_direct_apply_ack_missing",
    )
    require(
        immutable_submission(bound["settings"].data_dir, bound["rid"]) == bound["immutable"],
        "transport_original_submission_changed",
    )
    second = session._get(
        bound["process"].base, bound["settings"], "/api/ssh-defense/sessions/status"
    )
    require(
        second["owned_sessions"] == 0
        and second["continuous_execution"] is False
        and second["enabled"] is True,
        "transport_second_boot_has_owned_session",
    )


def _safe_error(error):
    value = (
        str(error) if isinstance(error, RestartAcceptanceError) else "transport_acceptance_failed"
    )
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value) else "transport_acceptance_failed"


def _original_task(bound):
    path = "/api/hosts/" + bound["host_id"] + "/ssh-defense/transactions/" + bound["rid"]
    task = session._get(bound["process"].base, bound["settings"], path)
    require(
        task["request_id"] == bound["rid"]
        and not task["query_required"]
        and task["manifest"]["sha256"] == bound["ledger"]["manifest_sha256"],
        "transport_original_task_changed",
    )
    return task["current_result"]


def run_transport_restart_browser(
    settings: Settings,
    *,
    stimulate_after_arm,
    snapshot,
    restart_transport,
    proof_path: Path,
) -> dict:
    """Fixed rule/direct-ACK profile; callback runs once before original query."""
    _require_callback(restart_transport)
    _require_callback(stimulate_after_arm)
    _require_callback(snapshot)
    _verified_source()
    require(
        proof_path.is_absolute() and proof_path.parent.is_dir() and not proof_path.exists(),
        "transport_proof_not_fresh",
    )
    original_path = proof_path.with_name(proof_path.stem + "-session.json")
    require(not original_path.exists(), "transport_session_proof_exists")
    require(_LOCK.acquire(blocking=False), "transport_restart_adapter_busy")
    once, lifecycle, ttl, callback_attempts = _Once(), None, None, 0
    record = {
        "schema": "opsark-defense-transport-restart-browser/v1",
        "completed": False,
        "transport_restart_acceptance_passed": False,
        "business_verdict": "pending",
        "business_recollection": False,
        "resident_modified": False,
        "session_driver_sha256": SESSION_DRIVER_SHA256,
        "restart_function_sha256": SESSION_RESTART_SHA256,
        "actual_transport_restart_independently_required": True,
    }

    def stimulus(cursor):
        try:
            return stimulate_after_arm(cursor)
        except Exception:
            raise RestartAcceptanceError("transport_stimulus_unavailable") from None

    def native_snapshot():
        try:
            return snapshot()
        except Exception:
            raise RestartAcceptanceError("transport_snapshot_unavailable") from None

    def restart(*args, **kwargs):
        nonlocal lifecycle, ttl, callback_attempts
        once.take()
        bound = inspect.signature(_ORIGINAL_RESTART).bind(*args, **kwargs).arguments
        _before_restart(bound)
        before = _original_task(bound)
        require(
            before["state"] == "active"
            and type(before["remaining_ms"]) is int
            and 0 < before["remaining_ms"] <= 60000,
            "transport_original_direct_ttl_missing",
        )
        callback_attempts += 1
        try:
            value = restart_transport()
        except Exception:
            raise RestartAcceptanceError("transport_restart_callback_unavailable") from None
        lifecycle = _restart_proof(value, bound)
        require(
            immutable_submission(settings.data_dir, bound["rid"]) == bound["immutable"],
            "transport_restart_changed_controller_submission",
        )
        result = _ORIGINAL_RESTART(*args, **kwargs)
        after = _original_task(bound)
        require(
            after["deadline_at"] == before["deadline_at"]
            and (
                after["state"] == "expired"
                and after["remaining_ms"] is None
                or after["state"] == "active"
                and type(after["remaining_ms"]) is int
                and 0 < after["remaining_ms"] <= before["remaining_ms"]
            ),
            "transport_original_ttl_increased",
        )
        ttl = {
            "state": after["state"],
            "remaining_ms_before": before["remaining_ms"],
            "remaining_ms_after": after["remaining_ms"],
            "not_increased": True,
            "original_deadline_unchanged": True,
        }
        return result

    try:
        with patch.object(session, "_restart", restart):
            original = _ORIGINAL_RUN(
                settings,
                stimulate_after_arm=stimulus,
                snapshot=native_snapshot,
                proof_path=original_path,
                expected_ack_behavior="direct_ack",
                expected_ai_calls=0,
            )
        require(
            original.get("completed") is True and original.get("session_acceptance_passed") is True,
            _safe_error(
                RestartAcceptanceError(original.get("failure_code", "transport_session_failed"))
            ),
        )
        require(
            once.calls == 1 and lifecycle is not None and ttl is not None,
            "transport_restart_not_verified",
        )
        require(
            original["ai_dispatches"] == 0
            and original["original_query_state"] in {"active", "expired"}
            and len(original["processes"]) == 2
            and original["processes"][1]["write_requests"] == {"query": 1}
            and original["processes"][1]["model_attempts"] == 0
            and original["business_verdict"] == "pending"
            and original["business_recollection"] is False,
            "transport_reconciliation_replayed_action",
        )
        record.update(
            completed=True,
            transport_restart_acceptance_passed=True,
            lifecycle=lifecycle,
            ttl=ttl,
            original_query_state=original["original_query_state"],
            controller_process_restart_verified=True,
            original_submission_unchanged=original["original_submission_unchanged"],
            original_session_history_preserved=original["original_session_history_preserved"],
            old_owner_readonly_verified=original["old_owner_readonly_verified"],
            terminal_phase=original["terminal_phase"],
            ai_dispatches=0,
            processes=original["processes"],
            original_ledger=original["original_ledger"],
            request_id_sha256=original["request_id_sha256"],
        )
        for name in (
            "production_root_invoker",
            "production_business_collector",
            "production_session_worker",
            "production_session_coordinator",
            "production_defense_ai",
            "production_http_transport",
        ):
            record[name] = original[name]
    except Exception as error:
        record["failure_code"] = _safe_error(error)
    finally:
        _LOCK.release()
    record["hook_invocations"] = once.calls
    record["restart_callback_attempts"] = callback_attempts
    if original_path.exists():
        record["original_session_proof_sha256"] = hashlib.sha256(
            original_path.read_bytes()
        ).hexdigest()
    _json(proof_path, record)
    return record


def _restart_proof(value, bound):
    """Only the closed native lifecycle facts leave this boundary."""
    keys = {
        "schema",
        "completed",
        "restart_count",
        "request_id_sha256",
        "manifest_sha256",
        "identity_binding_sha256",
        "before",
        "after",
        *RESTART_FLAGS,
        *ZERO_COUNTS,
        *ONE_COUNTS,
    }
    require(type(value) is dict and set(value) == keys, "transport_restart_proof_schema_changed")
    require(
        value["schema"] == "opsark-root-transport-restart-proof/v1"
        and value["completed"] is True
        and type(value["restart_count"]) is int
        and value["restart_count"] == 1
        and all(value[name] is True for name in RESTART_FLAGS)
        and all(type(value[name]) is int and value[name] == 0 for name in ZERO_COUNTS)
        and all(type(value[name]) is int and value[name] == 1 for name in ONE_COUNTS),
        "transport_restart_lifecycle_not_exact",
    )
    for name in ("request_id_sha256", "manifest_sha256", "identity_binding_sha256"):
        require(
            type(value[name]) is str and HEX.fullmatch(value[name]) is not None,
            "transport_restart_binding_not_digest",
        )
    require(
        value["request_id_sha256"] == hashlib.sha256(bound["rid"].encode()).hexdigest()
        and value["manifest_sha256"] == bound["ledger"]["manifest_sha256"]
        and value["identity_binding_sha256"] == bound["ledger"]["identity_binding_sha256"],
        "transport_restart_original_binding_changed",
    )
    for side in ("before", "after"):
        require(
            type(value[side]) is dict
            and set(value[side]) == set(PRESERVED + REPLACED)
            and all(
                type(item) is str and HEX.fullmatch(item) is not None
                for item in value[side].values()
            ),
            "transport_restart_state_not_digests",
        )
    require(
        all(value["before"][name] == value["after"][name] for name in PRESERVED),
        "transport_restart_protected_state_changed",
    )
    require(
        all(value["before"][name] != value["after"][name] for name in REPLACED),
        "transport_restart_old_transport_reused",
    )
    return {name: dict(item) if type(item) is dict else item for name, item in value.items()}
