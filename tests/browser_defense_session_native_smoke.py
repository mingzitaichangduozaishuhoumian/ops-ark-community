"""Real UI and worker single-session acceptance with opaque scoped callbacks.

Only mode, arm, session start and explicit original-task query are HTTP writes.
Prepare/apply/AI must originate in the production worker. No fake entry exists.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from browser_defense_native_smoke import _confirm, _login, _response
from defense_abrupt_process import immutable_submission, uncommitted_apply
from defense_recheck_process_restart import _json, _read, require
from defense_session_process import SessionProcess, _configuration
from playwright.sync_api import expect, sync_playwright

from opsark.config import Settings
from opsark.defense_ai import DefenseAIService, ModelInput
from opsark.defense_models import canonical, digest
from opsark.defense_session_models import SessionAIIntent, SessionDeclaration, SessionSelection
from opsark.defense_store import AIResult, AIUsagePermit, AliasMap, DefenseSource

SESSION_WAIT_SECONDS = 110
RESTART_OBSERVE_SECONDS = 5.5
TERMINAL = {"completed", "reconciliation_only", "expired", "stopped"}


def _sha(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _get(base, settings, path):
    status, raw, _ = _read(base, settings.token, path)
    require(status == 200, "session_read_unavailable")
    return json.loads(raw)


def _wait(read, predicate):
    deadline = time.monotonic() + SESSION_WAIT_SECONDS
    while True:
        value = read()
        if predicate(value):
            return value
        require(time.monotonic() < deadline, "session_worker_timeout")
        time.sleep(0.2)


def _ledger(directory, session_ref, rid):
    """Hash durable evidence without exporting rows, bytes or identifiers."""
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        db.row_factory = sqlite3.Row
        requests = db.execute(
            "SELECT op,request_sha256,request_bytes,dispatch_phase,reply_sha256,reply_bytes "
            "FROM defense_requests WHERE rid=? AND op IN ('prepare','apply') ORDER BY op",
            (rid,),
        ).fetchall()
        observations = db.execute(
            "SELECT op,state,accepted,receipt_sha256 FROM defense_observations "
            "WHERE rid=? AND op IN ('prepare','apply') ORDER BY rowid",
            (rid,),
        ).fetchall()
        fees = db.execute(
            "SELECT kind,state,count(*) AS count FROM defense_usage GROUP BY kind,state "
            "ORDER BY kind,state"
        ).fetchall()
        transaction = db.execute(
            "SELECT manifest_json,manifest_sha256 FROM defense_transactions WHERE rid=?", (rid,)
        ).fetchone()
        require(transaction is not None, "session_action_missing")
        manifest = json.loads(transaction["manifest_json"])
        immutable = {}
        for table in (
            "defense_sources",
            "defense_usage",
            "defense_ai_intents",
            "defense_ai_results",
            "defense_session_selections_v1",
            "defense_session_ai_v1",
            "defense_session_actions_v1",
            "defense_session_requests_v1",
        ):
            rows = db.execute("SELECT rowid,* FROM " + table + " ORDER BY rowid").fetchall()  # noqa: S608 -- fixed table literals only.
            immutable[table] = {"rows": len(rows), "sha256": _sha(repr([tuple(r) for r in rows]))}
        declaration = db.execute(
            "SELECT declaration_sha256,typed_declaration FROM defense_sessions_v1 "
            "WHERE session_ref=?",
            (session_ref,),
        ).fetchone()
        require(
            declaration is not None and _sha(declaration[1]) == declaration[0],
            "session_declaration_changed",
        )
        immutable["declaration"] = {"rows": 1, "sha256": declaration[0]}
        totals = {
            "sessions": db.execute("SELECT count(*) FROM defense_sessions_v1").fetchone()[0],
            "actions": db.execute(
                "SELECT count(*) FROM defense_transactions WHERE kind='action'"
            ).fetchone()[0],
            "apply_intents": db.execute(
                "SELECT count(*) FROM defense_requests WHERE op='apply'"
            ).fetchone()[0],
            "business_rechecks": db.execute("SELECT count(*) FROM defense_rechecks").fetchone()[0],
        }
        ai_evidence = _ai_evidence(db, session_ref, declaration)
    safe_requests = []
    for row in requests:
        require(_sha(row["request_bytes"]) == row["request_sha256"], "request_hash_changed")
        if row["reply_bytes"] is not None:
            require(_sha(row["reply_bytes"]) == row["reply_sha256"], "receipt_hash_changed")
        safe_requests.append(
            {key: row[key] for key in ("op", "request_sha256", "dispatch_phase", "reply_sha256")}
        )
    return {
        "totals": totals,
        "ai_evidence": ai_evidence,
        "requests": safe_requests,
        "observations": [dict(row) for row in observations],
        "fees": [dict(row) for row in fees],
        "immutable": immutable,
        "manifest_sha256": transaction["manifest_sha256"],
        "identity_binding_sha256": digest(
            {
                "action_id": manifest["action_id"],
                "manifest_sha256": transaction["manifest_sha256"],
                "cursor_id": manifest["cursor_id"],
            }
        ),
    }


def _sealed(model, row, sha_column, bytes_column):
    require(
        row is not None and _sha(row[bytes_column]) == row[sha_column], "ai_evidence_hash_changed"
    )
    value = model.model_validate_json(row[bytes_column])
    require(canonical(value) == row[bytes_column], "ai_evidence_schema_changed")
    return value


def _ai_evidence(db, session_ref, declaration_row):
    row = db.execute(
        "SELECT * FROM defense_session_ai_v1 WHERE session_ref=?", (session_ref,)
    ).fetchone()
    if row is None:
        return None
    declaration = SessionDeclaration.model_validate_json(declaration_row["typed_declaration"])
    sidecar = _sealed(SessionAIIntent, row, "sha256", "typed_record")
    selection_row = db.execute(
        "SELECT * FROM defense_session_selections_v1 WHERE session_ref=?", (session_ref,)
    ).fetchone()
    selection = _sealed(SessionSelection, selection_row, "sha256", "typed_record")
    permit_row = db.execute(
        "SELECT * FROM defense_ai_intents WHERE analysis_id=?", (sidecar.analysis_id,)
    ).fetchone()
    result_row = db.execute(
        "SELECT * FROM defense_ai_results WHERE analysis_id=?", (sidecar.analysis_id,)
    ).fetchone()
    permit = _sealed(AIUsagePermit, permit_row, "permit_sha256", "typed_permit")
    result = _sealed(AIResult, result_row, "result_sha256", "typed_result")
    source_row = db.execute(
        "SELECT * FROM defense_sources WHERE source_key=?", (permit.source_key,)
    ).fetchone()
    source = _sealed(DefenseSource, source_row, "source_sha256", "typed_source")
    aliases = _sealed(AliasMap, source_row, "alias_sha256", "alias_map")
    fee = db.execute(
        "SELECT * FROM defense_usage WHERE intent_key=?", (sidecar.intent_key,)
    ).fetchone()
    candidate = next(item for item in source.candidates if item.source_ref == selection.source_ref)
    summary = ModelInput.model_validate_json(
        canonical(
            {
                "v": 1,
                "candidates": [
                    {
                        "candidate_alias": "candidate-1",
                        "evidence_alias": "evidence-1",
                        "classification": "eligible",
                        "distinct_failure_ports": candidate.distinct_failure_ports,
                        "ttl_seconds": 60,
                    }
                ],
                "omitted_candidate_count": len(source.candidates) - 1,
            }
        )
    ).model_dump(mode="json")
    require(
        sidecar.session_ref == selection.session_ref == session_ref
        and sidecar.analysis_id == permit.analysis_id == result.analysis_id == row["analysis_id"]
        and sidecar.intent_key == permit.intent_key == result.intent_key == row["intent_key"]
        and sidecar.input_digest == permit.input_digest == result.input_digest
        and sidecar.provider_fingerprint
        == permit.provider_fingerprint
        == result.provider_fingerprint
        == declaration.runtime.provider_fingerprint
        and sidecar.selection_sha256 == digest(selection)
        and permit.rid == declaration.cursor_rid
        and permit.owner == declaration.boot_owner
        and permit.deadline_at == declaration.controller_deadline_at
        and permit.advice_authorization is None
        and len(aliases.aliases) == 1
        and aliases.aliases[0].source_ref == selection.source_ref
        and aliases.aliases[0].evidence_sha256 == selection.evidence_sha256
        and source == selection.source
        and candidate.classification == "eligible"
        and result.status == "completed"
        and result.decision == "propose_defense"
        and result.source_ref == selection.source_ref
        and result.evidence_sha256 == selection.evidence_sha256
        and result.input_digest
        == DefenseAIService._input_digest(source, summary, aliases, result.provider_fingerprint)
        and result.proof_sha256
        == DefenseAIService._proof(result, permit, source, declaration.runtime.context)
        and fee is not None
        and fee["kind"] == "ai"
        and fee["state"] == "consumed"
        and fee["provider_fingerprint"] == sidecar.provider_fingerprint
        and fee["rid"] == declaration.cursor_rid,
        "ai_evidence_bindings_changed",
    )
    return {
        "analysis_id_sha256": _sha(sidecar.analysis_id),
        "intent_key": sidecar.intent_key,
        "input_digest": sidecar.input_digest,
        "provider_fingerprint": sidecar.provider_fingerprint,
        "proof_sha256": result.proof_sha256,
        "permit_sha256": permit_row["permit_sha256"],
        "result_sha256": result_row["result_sha256"],
        "selection_sha256": sidecar.selection_sha256,
        "bounded_input_sha256": digest(summary),
        "status": "completed",
        "decision": "propose_defense",
        "fee_state": "consumed",
        "independent_bindings_verified": True,
    }


def _native(snapshot, *, expected_ack_behavior, rid, ledger):
    """A marker is not independent physical fault proof; export allowlist only."""
    value = snapshot()
    root = value["ledger"]
    require(root["usage_count"] == root["intents"] == 1, "root_usage_not_single")
    fault = value.get("projection", {}).get("apply_fault")
    result = {"usage_count": 1, "intents": 1, "fault_marker_bound": False}
    if expected_ack_behavior == "direct_ack":
        require(fault is None, "unexpected_apply_fault")
    else:
        require(isinstance(fault, dict), "native_fault_marker_missing")
        apply = next(row for row in ledger["requests"] if row["op"] == "apply")
        require(
            fault.get("request_ref") == rid
            and fault.get("request_sha256") == apply["request_sha256"]
            and fault.get("identity_binding_sha256") == ledger["identity_binding_sha256"]
            and fault.get("fault_layer") == "target_exact_ssh_socket_interruption"
            and fault.get("request_master_preserved") is True
            and fault.get("native_listener_preserved") is True
            and fault.get("root_cli_completed") is True
            and fault.get("after_absence") is True
            and fault.get("socket_close_exec_count") == 1
            and fault.get("session_signal_sent") is False,
            "native_fault_marker_unbound",
        )
        result.update(fault_marker_bound=True, fault_marker_sha256=_sha(canonical(fault)))
    return result


def _pending_summary(page, base, settings, prefix, output, private_ids):
    status, expected, _ = _read(base, settings.token, prefix + "/handoff")
    require(status == 200, "pending_handoff_unavailable")
    with page.expect_download() as downloaded:
        page.get_by_role("button", name="导出未复验摘要（待验收）", exact=True).click()
    raw = Path(downloaded.value.path()).read_bytes()
    require(raw == expected and len(raw) <= 65536, "pending_handoff_changed")
    text = raw.decode("utf-8")
    require(
        "当前验收：待验收" in text and "业务检查：待验收" in text, "unrechecked_handoff_not_pending"
    )
    require(
        not any(
            value in text
            for value in (
                settings.token,
                *private_ids,
                "198.18.241.",
                "key_file",
                "source_ref",
                "business.opsark.invalid",
                "-----BEGIN",
                "Bearer ",
                "PRIVATE_KEY",
                "DATABASE_URL",
                "https://",
                "http://",
                "@",
                "SELECT ",
                "INSERT ",
                '{"',
                "Traceback",
                "password=",
            )
        ),
        "private_handoff_content",
    )
    with output.open("xb") as stream:
        stream.write(raw)
    return _sha(raw)


def _safe_audit(audit):
    allowed = {
        "model_attempts",
        "model_requests",
        "read_requests",
        "write_requests",
        "forbidden_write_attempts",
        "production_http_transport",
        "production_root_invoker",
        "production_business_collector",
        "production_session_worker",
        "production_session_coordinator",
        "production_defense_ai",
        "worker_disabled",
        "session_worker_stopped",
        "stopped",
        "failure_type",
    }
    return {key: value for key, value in audit.items() if key in allowed}


def run_session_browser(
    settings: Settings,
    *,
    stimulate_after_arm: Callable[[str], dict],
    snapshot: Callable[[], dict],
    proof_path: Path,
    expected_ack_behavior: str,
    expected_ai_calls: int = 0,
) -> dict:
    """One explicit session, real worker, actual restart, original readonly query."""
    _configuration(settings, expected_ai_calls)
    require(
        expected_ack_behavior in {"direct_ack", "exact_apply_socket_loss"}, "invalid_ack_profile"
    )
    require(
        proof_path.is_absolute() and proof_path.parent.is_dir() and not proof_path.exists(),
        "proof_not_fresh",
    )
    require(
        settings.data_dir.is_absolute()
        and settings.data_dir.parent.is_dir()
        and not settings.data_dir.is_symlink()
        and not settings.data_dir.is_junction()
        and (not settings.data_dir.exists() or not any(settings.data_dir.iterdir())),
        "session_data_not_fresh",
    )
    processes = proof_path.parent / "controller-processes"
    require(not processes.exists(), "process_directory_exists")
    processes.mkdir(mode=0o700)
    record = {
        "schema": "opsark-defense-single-session-native-browser/v1",
        "completed": False,
        "session_acceptance_passed": False,
        "phase": "starting",
        "expected_ack_behavior": expected_ack_behavior,
        "expected_ai_calls": expected_ai_calls,
        "business_verdict": "pending",
        "business_recollection": False,
        "resident_modified": False,
        "actual_socket_fault_independently_required": True,
        "processes": [],
    }
    first = second = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                first = SessionProcess(settings, processes, 1, expected_ai_calls=expected_ai_calls)
                with first:
                    host_id = first.ready["host_id"]
                    context, page, errors = _login(browser, first.base, settings.token)
                    try:
                        cursor, reference, changed = _start(
                            page, settings, first, stimulate_after_arm
                        )
                        session_path = (
                            "/api/hosts/" + host_id + "/ssh-defense/sessions/" + reference
                        )
                        record["phase"] = "worker_only"
                        final = _wait(
                            lambda: _get(first.base, settings, session_path),
                            lambda value: value["effective_phase"] in TERMINAL,
                        )
                        wanted = (
                            "completed"
                            if expected_ack_behavior == "direct_ack"
                            else "reconciliation_only"
                        )
                        require(
                            final["phase"] == final["effective_phase"] == wanted
                            and final["business_verdict"] == "pending"
                            and final["requires_ai"] is bool(expected_ai_calls)
                            and final["cursor_request_id"] == cursor,
                            "worker_session_not_expected_terminal",
                        )
                        rid = final["action_request_id"]
                        require(isinstance(rid, str), "worker_action_missing")
                        ledger = _ledger(settings.data_dir, reference, rid)
                        pending = _assert_single_action(
                            ledger, settings, rid, expected_ai_calls, expected_ack_behavior
                        )
                        native = _native(
                            snapshot,
                            expected_ack_behavior=expected_ack_behavior,
                            rid=rid,
                            ledger=ledger,
                        )
                        immutable = immutable_submission(settings.data_dir, rid)
                        record.update(
                            session_ref_sha256=_sha(reference),
                            cursor_request_id_sha256=_sha(cursor),
                            request_id_sha256=_sha(rid),
                            terminal_phase=wanted,
                            declaration_sha256=final["declaration_sha256"],
                            original_ledger=ledger,
                            original_apply=pending,
                            native=native,
                            submission_sha256=immutable,
                            automatic_worker_action_verified=True,
                            automatic_mode_revision=changed["revision"],
                        )
                        require(not errors, "session_browser_error")
                    finally:
                        context.close()
                record["processes"].append(_safe_audit(first.audit))
                require(
                    first.audit["write_requests"] == {"mode": 1, "arm": 1, "session_start": 1},
                    "manual_http_action_substituted",
                )
                require(
                    first.audit["model_attempts"] == expected_ai_calls
                    and len(first.audit["model_requests"]) == expected_ai_calls,
                    "actual_model_attempt_count_changed",
                )
                if expected_ai_calls:
                    require(
                        ledger["ai_evidence"] is not None
                        and first.audit["model_requests"][0]["bounded_input_sha256"]
                        == ledger["ai_evidence"]["bounded_input_sha256"],
                        "actual_model_input_not_bound_to_original_proof",
                    )
                else:
                    require(ledger["ai_evidence"] is None, "rule_model_evidence_present")
                second = SessionProcess(settings, processes, 2, expected_ai_calls=expected_ai_calls)
                with second:
                    require(second.pid != first.pid, "session_process_pid_reused")
                    record["controller_process_restart_verified"] = True
                    record["phase"] = "restart_readonly"
                    _restart(
                        browser,
                        second,
                        settings,
                        session_path,
                        host_id,
                        reference,
                        cursor,
                        rid,
                        final,
                        ledger,
                        immutable,
                        proof_path.parent,
                        record,
                    )
                record["processes"].append(_safe_audit(second.audit))
                require(
                    second.audit["write_requests"] == {"query": 1}
                    and second.audit["model_attempts"] == 0,
                    "restart_sent_new_action_or_model",
                )
                for field in (
                    "production_root_invoker",
                    "production_business_collector",
                    "production_session_worker",
                    "production_session_coordinator",
                    "production_defense_ai",
                    "production_http_transport",
                ):
                    record[field] = all(item[field] for item in record["processes"])
                record.update(
                    completed=True,
                    session_acceptance_passed=True,
                    phase="completed",
                    ai_dispatches=first.audit["model_attempts"],
                    original_submission_unchanged=True,
                    original_session_history_preserved=True,
                    old_owner_readonly_verified=True,
                )
            finally:
                browser.close()
    except Exception as error:
        from defense_recheck_process_restart import RestartAcceptanceError

        record["failure_type"] = type(error).__name__
        if isinstance(error, RestartAcceptanceError):
            record["failure_code"] = str(error)
        for process in (first, second):
            if process is not None and process.audit:
                safe = _safe_audit(process.audit)
                if safe not in record["processes"]:
                    record["processes"].append(safe)
    _json(proof_path, record)
    return record


def _start(page, settings, process, stimulate):
    page.locator("#automation-mode-select").select_option("automatic")
    with _response(page, "/api/automation", method="PUT") as mode:
        page.locator("#save-automation-mode").click()
    changed = mode.value.json()
    require(
        mode.value.status == 200
        and changed["mode_sync_complete"]
        and changed["mode"] == "automatic",
        "automatic_not_synced",
    )
    page.locator('button[data-view="security"]').click()
    page.locator('[data-defense="arm"]').click()
    with _response(page, "/ssh-defense/arm") as armed:
        _confirm(page)
    require(armed.value.status == 200, "session_arm_failed")
    cursor = armed.value.json()["request_id"]
    require(stimulate(cursor)["cursor_request_id"] == cursor, "session_stimulus_changed")
    section = page.get_by_role("region", name="单次防护会话", exact=True)
    section.get_by_role("button", name="启动这一次防护会话", exact=True).click()
    with _response(page, "/ssh-defense/sessions") as started:
        _confirm(page)
    require(started.value.status == 200, "session_start_failed")
    reference = started.value.json()["session_ref"]
    body = started.value.request.post_data_json
    require(
        body["session_ref"] == reference
        and body["cursor_request_id"] == cursor
        and body["confirm_session"] is True,
        "session_reference_changed",
    )
    return cursor, reference, changed


def _assert_single_action(ledger, settings, rid, expected_ai_calls, behavior):
    require(
        ledger["totals"]
        == {"sessions": 1, "actions": 1, "apply_intents": 1, "business_rechecks": 0},
        "session_action_count_changed",
    )
    require(
        ledger["fees"]
        == ([{"kind": "ai", "state": "consumed", "count": 1}] if expected_ai_calls else [])
        + [
            {
                "kind": "execution",
                "state": "consumed" if behavior == "direct_ack" else "unknown",
                "count": 1,
            }
        ],
        "session_fee_count_changed",
    )
    prepare_ack = [
        row
        for row in ledger["observations"]
        if row["op"] == "prepare" and row["accepted"] == 1 and row["state"] == "ready"
    ]
    apply_ack = [
        row
        for row in ledger["observations"]
        if row["op"] == "apply" and row["accepted"] == 1 and row["state"] == "active"
    ]
    require(len(prepare_ack) == 1, "direct_prepare_ack_missing")
    pending = uncommitted_apply(settings.data_dir, rid)
    require(
        (len(apply_ack) == 1 and pending["reply_committed"])
        if behavior == "direct_ack"
        else (
            not apply_ack
            and not pending["reply_committed"]
            and pending["dispatch_phase"] in {"sendable", "unknown"}
            and pending["query_required"]
        ),
        "apply_ack_profile_changed",
    )
    return pending


def _restart(
    browser,
    process,
    settings,
    session_path,
    host_id,
    reference,
    cursor,
    rid,
    final,
    ledger,
    immutable,
    directory,
    record,
):
    original = _get(process.base, settings, session_path)
    require(
        original["session_ref"] == reference
        and original["cursor_request_id"] == cursor
        and original["action_request_id"] == rid
        and original["declaration_sha256"] == final["declaration_sha256"]
        and original["owned_by_current_boot"] is False
        and original["can_stop"] is False,
        "old_session_owner_reacquired",
    )
    history = _get(process.base, settings, "/api/hosts/" + host_id + "/ssh-defense/sessions")
    require(
        len(history["sessions"]) == 1 and history["sessions"][0]["session_ref"] == reference,
        "original_session_history_missing",
    )
    context, page, errors = _login(browser, process.base, settings.token)
    try:
        page.locator('button[data-view="security"]').click()
        section = page.get_by_role("region", name="单次防护会话", exact=True)
        section.locator("button").filter(has_text=reference).click()
        expect(section.get_by_role("button", name="核对并停止原会话", exact=True)).to_have_count(0)
        prefix = "/api/hosts/" + host_id + "/ssh-defense/transactions/" + rid
        with _response(page, "/transactions/" + rid + "/query") as queried:
            section.get_by_role("button", name="只读核对原任务", exact=True).click()
        require(queried.value.status == 200, "original_action_query_failed")
        task = queried.value.json()
        require(
            task["request_id"] == rid
            and task["manifest"]["sha256"] == ledger["manifest_sha256"]
            and task["current_result"]["state"] in {"active", "expired"}
            and not task["query_required"],
            "original_action_not_reconciled",
        )
        reconciled = _get(process.base, settings, session_path)
        require(
            reconciled["phase"] == final["phase"]
            and reconciled["effective_phase"] == final["effective_phase"]
            and reconciled["can_stop"] is False
            and reconciled["business_verdict"] == "pending",
            "query_promoted_or_reopened_session",
        )
        record["original_query_state"] = task["current_result"]["state"]
        record["pending_summary_sha256"] = _pending_summary(
            page,
            process.base,
            settings,
            prefix,
            directory / "session-business-pending.md",
            (host_id, rid, cursor, reference),
        )
        page.wait_for_timeout(RESTART_OBSERVE_SECONDS * 1000)
        require(not errors, "restart_browser_error")
    finally:
        context.close()
    after = _ledger(settings.data_dir, reference, rid)
    require(
        after["immutable"] == ledger["immutable"]
        and immutable_submission(settings.data_dir, rid) == immutable,
        "restart_changed_original_evidence",
    )
    require(
        after["totals"] == ledger["totals"] and after["fees"] == ledger["fees"],
        "restart_replayed_or_recharged",
    )
    require(
        _get(process.base, settings, "/api/automation")["mode"] == "automatic",
        "restart_changed_automation_mode",
    )
