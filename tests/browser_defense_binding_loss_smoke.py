"""A protected-listener restart must invalidate current Root trust, not replay.

The first rule/direct-ACK session remains historical. A separate negative
acceptance requires one new unknown/binding_changed receipt and conservative
Controller state, while the original sender, charge identity and evidence stay.
"""

from __future__ import annotations

import hashlib
import inspect
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import browser_defense_session_native_smoke as session
import browser_defense_transport_restart_smoke as transport
import defense_session_process
from browser_defense_native_smoke import _login, _response
from defense_recheck_process_restart import RestartAcceptanceError, _json, require
from playwright.sync_api import expect

from opsark.config import Settings
from opsark.defense_models import DefenseReply, canonical, digest

TRANSPORT_ADAPTER_SHA256 = "0348ccd2a9ca23123f60e2ee1908154b3801bf8200a31164e25015554d0917be"
PROCESS_SHA256 = "0caa1ad66ebdb718d6087cd133ae1f8e287b7c23e2485d3f806f9cd8ad4ea239"
OBSERVED = "binding_loss_expected_negative_observed"
# Both adapters replace the same frozen module hook; serialize their lifetime.
_LOCK = transport._LOCK
PRESERVED = (
    "protocol_process_sha256",
    "protocol_listener_sha256",
    "netns_sha256",
    "protected_log_identity_sha256",
    "protected_log_prefix_sha256",
    "public_pin_sha256",
    "key_file_identity_sha256",
    "protected_config_sha256",
    "protocol_config_sha256",
    "roles_policy_sha256",
    "authority_sha256",
    "root_ledger_sha256",
    "root_grants_sha256",
    "root_usage_sha256",
    "root_intents_sha256",
    "root_binding_sha256",
)
REPLACED = ("protected_process_sha256", "protected_listener_sha256", "current_binding_sha256")
TRUE_FLAGS = (
    "old_protected_terminated",
    "new_protected_started",
    "protected_identity_changed",
    "protected_listening",
    "protocol_listener_preserved",
    "immutable_root_preserved",
    "protected_log_prefix_preserved",
    "binding_changed",
)


def _verified_source():
    transport._verified_source()
    require(
        hashlib.sha256(Path(transport.__file__).read_bytes()).hexdigest()
        == TRANSPORT_ADAPTER_SHA256,
        "binding_loss_adapter_source_changed",
    )
    require(
        hashlib.sha256(Path(defense_session_process.__file__).read_bytes()).hexdigest()
        == PROCESS_SHA256,
        "binding_loss_process_source_changed",
    )


def _core(directory, rid):
    """Original evidence plus charge identity, excluding its conservative state."""
    queries = (
        "SELECT rowid,rid,kind,host_id,defense_scope,context_json,context_sha256,owner,"
        "deadline_at,cursor_rid,created_at,manifest_sha256,manifest_json,action_id "
        "FROM defense_transactions WHERE rid=?",
        "SELECT rowid,* FROM defense_requests "
        "WHERE rid=? AND op IN ('prepare','apply') ORDER BY op",
        "SELECT rowid,* FROM defense_authorizations WHERE rid=? ORDER BY rowid",
        "SELECT rowid,intent_key,kind,rid,host_id,defense_scope,grant_ref,charged_day,"
        "provider_fingerprint,created_at FROM defense_usage WHERE rid=? ORDER BY rowid",
    )
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        parts = [db.execute(query, (rid,)).fetchall() for query in queries]
        charge = db.execute(
            "SELECT state,count(*) FROM defense_usage WHERE rid=? GROUP BY state", (rid,)
        ).fetchall()
        confirmed = db.execute(
            "SELECT rowid,* FROM defense_last_confirmed WHERE rid=?", (rid,)
        ).fetchall()
        queries_count = db.execute(
            "SELECT count(*) FROM defense_observations WHERE rid=? AND op='query'", (rid,)
        ).fetchone()[0]
    return {
        "originals_sha256": hashlib.sha256(repr(parts).encode()).hexdigest(),
        "charge_identity_sha256": hashlib.sha256(repr(parts[-1]).encode()).hexdigest(),
        "charge_rows": len(parts[-1]),
        "charge_states": charge,
        "last_confirmed_sha256": hashlib.sha256(repr(confirmed).encode()).hexdigest(),
        "query_observations": queries_count,
    }


def _query_receipt(directory, rid, ledger):
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute(
            "SELECT state,accepted,reason,receipt_sha256,receipt_bytes "
            "FROM defense_observations WHERE rid=? AND op='query' ORDER BY rowid",
            (rid,),
        ).fetchall()
    require(
        len(rows) == 1
        and rows[0][0:3] == ("unknown", 0, "unknown")
        and type(rows[0][4]) is bytes
        and hashlib.sha256(rows[0][4]).hexdigest() == rows[0][3],
        "binding_loss_query_receipt_missing",
    )
    reply = DefenseReply.parse(rows[0][4])
    require(
        canonical(reply) + b"\n" == rows[0][4]
        and reply.op == "query"
        and reply.request_id == rid
        and reply.state == "unknown"
        and reply.reason_code == "binding_changed"
        and reply.manifest_sha256 == ledger["manifest_sha256"]
        and digest(
            {
                "action_id": reply.action_id,
                "manifest_sha256": reply.manifest_sha256,
                "cursor_id": reply.cursor_id,
            }
        )
        == ledger["identity_binding_sha256"],
        "binding_loss_wrong_root_reason_or_original",
    )
    return {
        "root_state": "unknown",
        "root_reason": "binding_changed",
        "accepted": False,
        "controller_reason": "unknown",
        "receipt_sha256": rows[0][3],
    }


def _negative_ui(bound):
    browser, process, settings = bound["browser"], bound["process"], bound["settings"]
    rid, reference, host = bound["rid"], bound["reference"], bound["host_id"]
    old = session._get(process.base, settings, bound["session_path"])
    require(
        old["owned_by_current_boot"] is False
        and old["can_stop"] is False
        and old["phase"] == old["effective_phase"] == "completed"
        and old["action_request_id"] == rid
        and old["declaration_sha256"] == bound["final"]["declaration_sha256"],
        "binding_loss_old_session_changed",
    )
    history = session._get(process.base, settings, "/api/hosts/" + host + "/ssh-defense/sessions")
    require(
        len(history["sessions"]) == 1 and history["sessions"][0]["session_ref"] == reference,
        "binding_loss_session_history_missing",
    )
    context, page, errors = _login(browser, process.base, settings.token)
    try:
        page.locator('button[data-view="security"]').click()
        section = page.get_by_role("region", name="单次防护会话", exact=True)
        section.locator("button").filter(has_text=reference).click()
        expect(section.get_by_role("button", name="核对并停止原会话", exact=True)).to_have_count(0)
        with _response(page, "/transactions/" + rid + "/query") as response:
            section.get_by_role("button", name="只读核对原任务", exact=True).click()
        # HTTP status is evidence, not the outcome. Read the durable local task
        # and exact Root receipt even if API error presentation changes later.
        status = response.value.status
        path = "/api/hosts/" + host + "/ssh-defense/transactions/" + rid
        task = session._get(process.base, settings, path)
        require(
            task["request_id"] == rid
            and task["manifest"]["sha256"] == bound["ledger"]["manifest_sha256"]
            and task["phase"] == "unknown"
            and task["query_required"] is True
            and task["current_result"] is None
            and task["reason_code"] == "unknown"
            and task["last_confirmed"]["state"] == "active",
            "binding_loss_current_state_was_promoted",
        )
        detail = page.locator('[data-defense="detail"]')
        expect(detail).to_contain_text("结果未确认，只查询原任务")
        expect(detail).to_contain_text("旧成功记录不能替代本次结果")
        expect(
            section.get_by_role("button", name="启动这一次防护会话", exact=True)
        ).to_be_disabled()
        summary_sha = session._pending_summary(
            page,
            process.base,
            settings,
            path,
            bound["directory"] / "binding-loss-business-pending.md",
            (host, rid, bound["cursor"], reference),
        )
        text = (bound["directory"] / "binding-loss-business-pending.md").read_text(encoding="utf-8")
        require(
            "原任务仍待查询对账" in text and "当前本地对账：未取得可信查询" in text,
            "binding_loss_handoff_falsely_current",
        )
        require(not errors, "binding_loss_browser_error")
    finally:
        context.close()
    after = session._get(process.base, settings, bound["session_path"])
    require(
        after["phase"] == after["effective_phase"] == "completed"
        and after["business_verdict"] == "pending"
        and after["can_stop"] is False,
        "binding_loss_historical_session_was_rewritten",
    )
    return {
        "query_http_status": status,
        "query_required": True,
        "current_root_verified": False,
        "historical_session_phase": "completed",
        "historical_last_confirmed_state": "active",
        "historical_session_is_not_current_recovery": True,
        "pending_summary_sha256": summary_sha,
    }


def run_binding_loss_browser(
    settings: Settings,
    *,
    stimulate_after_arm,
    snapshot,
    restart_protected_listener,
    proof_path: Path,
):
    """Independent negative acceptance; base success remains explicitly false."""
    _verified_source()
    for callback in (stimulate_after_arm, snapshot, restart_protected_listener):
        transport._require_callback(callback)
    require(
        proof_path.is_absolute() and proof_path.parent.is_dir() and not proof_path.exists(),
        "binding_loss_proof_not_fresh",
    )
    base_path = proof_path.with_name(proof_path.stem + "-session.json")
    require(not base_path.exists(), "binding_loss_base_proof_exists")
    require(_LOCK.acquire(blocking=False), "binding_loss_adapter_busy")
    once, lifecycle, observed, callback_attempts = transport._Once(), None, None, 0
    record = {
        "schema": "opsark-defense-binding-loss-browser/v1",
        "negative_acceptance_passed": False,
        "base_completed": False,
        "business_verdict": "pending",
        "business_recollection": False,
        "resident_modified": False,
        "session_driver_sha256": transport.SESSION_DRIVER_SHA256,
        "restart_function_sha256": transport.SESSION_RESTART_SHA256,
        "process_source_sha256": PROCESS_SHA256,
        "actual_binding_loss_independently_required": True,
    }

    def stimulus(cursor):
        try:
            return stimulate_after_arm(cursor)
        except Exception:
            raise RestartAcceptanceError("binding_loss_stimulus_unavailable") from None

    def native_snapshot():
        try:
            return snapshot()
        except Exception:
            raise RestartAcceptanceError("binding_loss_snapshot_unavailable") from None

    def restart(*args, **kwargs):
        nonlocal lifecycle, observed, callback_attempts
        once.take()
        bound = inspect.signature(transport._ORIGINAL_RESTART).bind(*args, **kwargs).arguments
        transport._before_restart(bound)
        before = _core(settings.data_dir, bound["rid"])
        require(
            before["charge_states"] == [("consumed", 1)] and before["query_observations"] == 0,
            "binding_loss_prior_query_or_charge_changed",
        )
        callback_attempts += 1
        try:
            value = restart_protected_listener()
        except Exception:
            raise RestartAcceptanceError("binding_loss_callback_unavailable") from None
        lifecycle = _restart_proof(value, bound)
        require(
            _core(settings.data_dir, bound["rid"]) == before,
            "binding_loss_restart_mutated_controller",
        )
        ui = _negative_ui(bound)
        query = _query_receipt(settings.data_dir, bound["rid"], bound["ledger"])
        after = _core(settings.data_dir, bound["rid"])
        require(
            after["originals_sha256"] == before["originals_sha256"]
            and after["charge_identity_sha256"] == before["charge_identity_sha256"]
            and before["charge_rows"] == after["charge_rows"] == 1
            and before["last_confirmed_sha256"] == after["last_confirmed_sha256"]
            and after["charge_states"] == [("unknown", 1)]
            and after["query_observations"] == 1,
            "binding_loss_originals_or_charge_replaced",
        )
        old = bound["ledger"]
        current = session._ledger(settings.data_dir, bound["reference"], bound["rid"])
        require(
            {key: value for key, value in old["immutable"].items() if key != "defense_usage"}
            == {key: value for key, value in current["immutable"].items() if key != "defense_usage"}
            and current["totals"] == old["totals"]
            and session._get(bound["process"].base, settings, "/api/automation")["mode"]
            == "automatic",
            "binding_loss_evidence_or_mode_changed",
        )
        observed = {
            **ui,
            **query,
            "originals_sha256": after["originals_sha256"],
            "charge_identity_sha256": after["charge_identity_sha256"],
            "charge_count": 1,
            "charge_state_before": "consumed",
            "charge_state_after": "unknown",
            "last_confirmed_sha256": after["last_confirmed_sha256"],
            "source_and_session_sidecars_preserved": True,
        }
        raise RestartAcceptanceError(OBSERVED)

    try:
        with patch.object(session, "_restart", restart):
            base = transport._ORIGINAL_RUN(
                settings,
                stimulate_after_arm=stimulus,
                snapshot=native_snapshot,
                proof_path=base_path,
                expected_ack_behavior="direct_ack",
                expected_ai_calls=0,
            )
        require(
            base.get("completed") is False
            and base.get("session_acceptance_passed") is False
            and base.get("failure_code") == OBSERVED
            and observed is not None
            and lifecycle is not None
            and once.calls == callback_attempts == 1,
            "binding_loss_negative_boundary_not_observed",
        )
        require(
            len(base["processes"]) == 2
            and all(item["stopped"] and item["model_attempts"] == 0 for item in base["processes"])
            and base["processes"][1]["write_requests"] == {"query": 1},
            "binding_loss_replayed_or_reanalyzed",
        )
        record.update(
            negative_acceptance_passed=True,
            outcome="expected_binding_loss_observed",
            base_termination="expected_negative_observation",
            base_completed=False,
            lifecycle=lifecycle,
            observation=observed,
            processes=base["processes"],
            ai_dispatches=0,
            original_submission_identity_preserved=True,
            controller_process_restart_verified=base["controller_process_restart_verified"],
            request_id_sha256=base["request_id_sha256"],
        )
        for name in (
            "production_root_invoker",
            "production_business_collector",
            "production_session_worker",
            "production_session_coordinator",
            "production_defense_ai",
            "production_http_transport",
        ):
            record[name] = all(item[name] for item in base["processes"])
    except Exception as error:
        record["failure_code"] = transport._safe_error(error)
    finally:
        _LOCK.release()
    record.update(hook_invocations=once.calls, restart_callback_attempts=callback_attempts)
    if base_path.exists():
        record["base_proof_sha256"] = hashlib.sha256(base_path.read_bytes()).hexdigest()
    _json(proof_path, record)
    return record


def _restart_proof(value, bound):
    keys = {
        "schema",
        "completed",
        "restart_count",
        "request_id_sha256",
        "manifest_sha256",
        "identity_binding_sha256",
        "before",
        "after",
        "execution_continuation_supported",
        *TRUE_FLAGS,
        *transport.ZERO_COUNTS,
        *transport.ONE_COUNTS,
    }
    require(type(value) is dict and set(value) == keys, "binding_loss_proof_schema_changed")
    require(
        value["schema"] == "opsark-protected-listener-restart-proof/v1"
        and value["completed"] is True
        and type(value["restart_count"]) is int
        and value["restart_count"] == 1
        and value["execution_continuation_supported"] is False
        and all(value[name] is True for name in TRUE_FLAGS)
        and all(type(value[name]) is int and value[name] == 0 for name in transport.ZERO_COUNTS)
        and all(type(value[name]) is int and value[name] == 1 for name in transport.ONE_COUNTS),
        "binding_loss_lifecycle_not_exact",
    )
    for name in ("request_id_sha256", "manifest_sha256", "identity_binding_sha256"):
        require(
            type(value[name]) is str and transport.HEX.fullmatch(value[name]) is not None,
            "binding_loss_binding_not_digest",
        )
    require(
        value["request_id_sha256"] == hashlib.sha256(bound["rid"].encode()).hexdigest()
        and value["manifest_sha256"] == bound["ledger"]["manifest_sha256"]
        and value["identity_binding_sha256"] == bound["ledger"]["identity_binding_sha256"],
        "binding_loss_original_binding_changed",
    )
    for side in ("before", "after"):
        require(
            type(value[side]) is dict
            and set(value[side]) == set(PRESERVED + REPLACED)
            and all(
                type(item) is str and transport.HEX.fullmatch(item) is not None
                for item in value[side].values()
            ),
            "binding_loss_state_not_digests",
        )
    require(
        all(value["before"][name] == value["after"][name] for name in PRESERVED),
        "binding_loss_protocol_or_root_originals_changed",
    )
    require(
        all(value["before"][name] != value["after"][name] for name in REPLACED)
        and value["before"]["current_binding_sha256"] == value["before"]["root_binding_sha256"]
        and value["after"]["current_binding_sha256"] != value["after"]["root_binding_sha256"],
        "binding_loss_live_binding_not_changed",
    )
    return {name: dict(item) if type(item) is dict else item for name, item in value.items()}
