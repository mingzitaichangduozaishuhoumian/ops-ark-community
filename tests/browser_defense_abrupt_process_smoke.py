"""Original-task recovery after an actual child os._exit before unknown commit."""

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path

from browser_defense_business_smoke import download
from browser_defense_native_smoke import _confirm, _login, _response
from defense_abrupt_process import (
    BOUNDARY,
    EXIT_CODE,
    AbruptProcess,
    immutable_submission,
    uncommitted_apply,
)
from defense_live_process import LiveProcess, apply_record
from defense_recheck_process_restart import (
    OriginalHistory,
    RestartAcceptanceError,
    StoredRun,
    _read,
    require,
    sealed_runs,
)
from playwright.sync_api import expect, sync_playwright

from opsark.config import Settings


def _summary(directory, filename, text, settings, host_id, rid):
    for value in (
        settings.token,
        host_id,
        rid,
        "198.18.241.",
        "key_file",
        "source_ref",
        "business.opsark.invalid",
        "-----BEGIN",
    ):
        require(value not in text, "private_summary_content")
    raw = text.encode("utf-8")
    with (directory / filename).open("xb") as output:
        output.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _task(base, settings, prefix):
    status, raw, _ = _read(base, settings.token, prefix)
    require(status == 200, "original_task_unavailable")
    return json.loads(raw)


def _download_for_run(page, base, settings, prefix, run_ref):
    status, raw, _ = _read(base, settings.token, prefix + "/handoff?run_ref=" + run_ref)
    require(status == 200, "expected_handoff_unavailable")
    text = download(page, "导出所选复验的安全摘要")
    require(
        hashlib.sha256(text.encode("utf-8")).digest() == hashlib.sha256(raw).digest(),
        "download_wrong_run",
    )
    return text


def run_abrupt_process_browser(
    settings: Settings,
    *,
    stimulate_after_arm: Callable[[str], dict],
    change_phase: Callable[[str], dict],
    snapshot: Callable[[], dict],
    proof_path: Path,
) -> dict:
    """Abrupt process termination, one apply, original query and business checks.

    The fixture callbacks only stimulate fixed failures/change HTTP phases and
    inspect native state. They never supply a product receipt or business result.
    An expired first query proves reconciliation only, never prior activation.
    """
    require(
        proof_path.is_absolute() and proof_path.parent.is_dir() and not proof_path.exists(),
        "proof_not_fresh",
    )
    require(
        settings.data_dir.is_absolute() and settings.data_dir.parent.is_dir(), "data_parent_missing"
    )
    require(
        not settings.data_dir.is_symlink() and not settings.data_dir.is_junction(),
        "linked_data_directory",
    )
    require(
        not settings.data_dir.exists() or not any(settings.data_dir.iterdir()), "data_not_empty"
    )
    processes = proof_path.parent / "controller-processes"
    require(not processes.exists(), "process_directory_exists")
    processes.mkdir(mode=0o700)
    record = {
        "schema": "opsark-defense-abrupt-controller-restart/v1",
        "completed": False,
        "flow_completed": False,
        "phase": "starting",
        "ai_dispatches": 0,
        "resident_modified": False,
        "controller_process_restart_verified": False,
        "live_root_reconnect_verified": False,
        "host_or_container_restart_verified": False,
        "full_current_acceptance": False,
        "os_exit_boundary_verified": False,
        "actual_socket_fault_independently_required": True,
        "processes": [],
        "runs": [],
    }
    first = second = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                first = AbruptProcess(settings, processes, 1)
                with first:
                    record["phase"] = "first_process_original_action"
                    host_id = first.ready["host_id"]
                    context, page, errors = _login(browser, first.base, settings.token)
                    try:
                        page.locator("#automation-mode-select").select_option("assisted")
                        with _response(page, "/api/automation", method="PUT") as mode:
                            page.locator("#save-automation-mode").click()
                        require(
                            mode.value.status == 200 and mode.value.json()["mode_sync_complete"],
                            "mode_not_synced",
                        )
                        page.locator('button[data-view="security"]').click()
                        page.locator('[data-defense="arm"]').click()
                        with _response(page, "/ssh-defense/arm") as armed:
                            _confirm(page)
                        require(armed.value.status == 200, "arm_failed")
                        cursor = armed.value.json()["request_id"]
                        require(
                            stimulate_after_arm(cursor)["cursor_request_id"] == cursor,
                            "fixture_cursor_changed",
                        )
                        with _response(page, "/transactions/" + cursor + "/query") as observed:
                            page.get_by_role("button", name="查询同一个原任务", exact=True).click()
                        require(observed.value.status == 200, "source_query_failed")
                        page.locator('[name="ssh-defense-source"]:enabled').check()
                        with _response(page, "/ssh-defense/prepare") as prepared:
                            page.get_by_role(
                                "button", name="准备处置清单（不执行）", exact=True
                            ).click()
                        require(prepared.value.status == 200, "prepare_failed")
                        action = prepared.value.json()
                        rid = action["request_id"]
                        prefix = "/api/hosts/" + host_id + "/ssh-defense/transactions/" + rid
                        record.update(
                            request_id=rid,
                            cursor_request_id=cursor,
                            manifest_sha256=action["manifest"]["sha256"],
                        )
                        page.get_by_role("button", name="核对并执行这份清单", exact=True).click()
                        with page.expect_event(
                            "requestfailed",
                            predicate=lambda request: (
                                request.method == "POST"
                                and request.url.endswith("/transactions/" + rid + "/apply")
                            ),
                        ) as failed:
                            _confirm(page)
                        require(failed.value.response() is None, "apply_received_response")
                        record["apply_request_failed_without_response"] = True
                        original_apply = apply_record(settings.data_dir, rid)
                        require(
                            original_apply["total_apply_intents"] == 1, "apply_intent_duplicated"
                        )
                        record["original_apply"] = original_apply
                        pending = uncommitted_apply(settings.data_dir, rid)
                        require(
                            pending
                            == {
                                "dispatch_phase": "sendable",
                                "reply_committed": False,
                                "transaction_phase": "apply_sendable",
                                "query_required": True,
                                "apply_observations": 0,
                            },
                            "unknown_was_already_committed",
                        )
                        immutable_before = immutable_submission(settings.data_dir, rid)
                        record["submission_before_sha256"] = immutable_before
                        record["uncommitted_apply_before_restart"] = pending
                        record["phase"] = "unavailable_commit_prevented_by_os_exit"
                        require(not errors, "browser_first_error")
                    finally:
                        context.close()
                record["processes"].append(first.audit)
                marker = first.audit["boundary"]
                require(
                    marker["boundary"] == BOUNDARY
                    and marker["request_ref_sha256"]
                    == hashlib.sha256(rid.encode("ascii")).hexdigest()
                    and marker["request_sha256"] == original_apply["request_sha256"]
                    and first.audit["actual_exit_code"] == EXIT_CODE
                    and not marker["reply_committed"]
                    and not marker["unavailable_observation_committed"],
                    "crash_marker_changed",
                )
                record["os_exit_boundary_verified"] = True
                record["actual_process_exit_code"] = first.audit["actual_exit_code"]
                require(
                    first.audit["write_requests"].get("apply") == 1, "first_apply_count_changed"
                )
                require(
                    first.audit["write_requests"].get("arm")
                    == first.audit["write_requests"].get("prepare")
                    == 1,
                    "first_action_count_changed",
                )
                second = LiveProcess(settings, processes, 2)
                with second:
                    require(second.pid != first.pid, "process_pid_reused")
                    record["controller_process_restart_verified"] = True
                    record["phase"] = "second_process_original_task"
                    require(second.ready["host_id"] == host_id, "restart_target_changed")
                    unknown = _task(second.base, settings, prefix)
                    require(
                        unknown["manifest"]["sha256"] == record["manifest_sha256"],
                        "restart_manifest_changed",
                    )
                    require(
                        unknown["request_id"] == rid
                        and unknown["query_required"]
                        and unknown["current_result"] is None,
                        "restart_lost_unknown",
                    )
                    require(
                        apply_record(settings.data_dir, rid) == original_apply,
                        "restart_changed_apply",
                    )
                    require(
                        immutable_submission(settings.data_dir, rid) == immutable_before,
                        "restart_changed_original_submission",
                    )
                    record["unknown_preserved_after_restart"] = True
                    context, page, errors = _login(browser, second.base, settings.token)
                    try:
                        page.locator('button[data-view="security"]').click()
                        page.locator('[data-defense="history"]').get_by_role("button").filter(
                            has_text=rid
                        ).click()
                        with _response(page, "/transactions/" + rid + "/query") as queried:
                            page.get_by_role("button", name="查询同一个原任务", exact=True).click()
                        require(queried.value.status == 200, "original_query_failed")
                        reconciled = queried.value.json()
                        require(
                            reconciled["manifest"]["sha256"] == record["manifest_sha256"],
                            "query_manifest_changed",
                        )
                        state = reconciled["current_result"]["state"]
                        require(
                            state in {"active", "expired"} and not reconciled["query_required"],
                            "original_query_not_closed",
                        )
                        record["first_reconciled_state"] = state
                        active_confirmed = state == "active"
                        if active_confirmed:
                            page.get_by_role("button", name="核对并撤销原动作", exact=True).click()
                            with _response(page, "/transactions/" + rid + "/revoke") as revoked:
                                _confirm(page)
                            require(revoked.value.status in {200, 409}, "revoke_failed")
                            if revoked.value.status == 200:
                                terminal = revoked.value.json()["current_result"]["state"]
                            else:
                                with _response(page, "/transactions/" + rid + "/query") as expired:
                                    page.get_by_role(
                                        "button", name="查询同一个原任务", exact=True
                                    ).click()
                                require(expired.value.status == 200, "expiry_query_failed")
                                terminal = expired.value.json()["current_result"]["state"]
                            require(terminal in {"revoked", "expired"}, "action_still_active")
                        else:
                            terminal = "expired"
                        record["terminal_state"] = terminal
                        page.locator("#automation-mode-select").select_option("manual")
                        with _response(page, "/api/automation", method="PUT") as manual:
                            page.locator("#save-automation-mode").click()
                        require(
                            manual.value.status == 200 and manual.value.json()["mode"] == "manual",
                            "manual_not_saved",
                        )
                        page.get_by_role("button", name="刷新只读复验历史", exact=True).click()
                        with page.expect_download() as pending:
                            page.get_by_role(
                                "button", name="导出未复验摘要（待验收）", exact=True
                            ).click()
                        text = Path(pending.value.path()).read_text(encoding="utf-8")
                        require("当前验收：待验收" in text, "unrechecked_was_green")
                        record["before_recheck_summary_sha256"] = _summary(
                            proof_path.parent, "business-before.md", text, settings, host_id, rid
                        )
                        for phase, verdict in (
                            ("mixed", "failed"),
                            ("timeout_only", "pending"),
                            ("restored", "passed"),
                        ):
                            record["phase"] = phase
                            require(type(change_phase(phase)) is dict, "fixture_phase_unconfirmed")
                            page.get_by_role("button", name="运行只读复验", exact=True).click()
                            started = time.monotonic()
                            with _response(page, "/transactions/" + rid + "/rechecks") as checked:
                                _confirm(page)
                            require(checked.value.status == 200, "recheck_failed")
                            run = checked.value.json()
                            require(
                                run["request_id"] == rid
                                and run["status"] == "completed"
                                and run["historical_verdict"] == verdict,
                                "recheck_verdict_changed",
                            )
                            expected_current = (
                                verdict if verdict != "passed" or active_confirmed else "pending"
                            )
                            require(
                                run["current_verdict"] == expected_current,
                                "recheck_current_verdict_changed",
                            )
                            projection = run["projection"]
                            # No unavailable observation was committed before os._exit.
                            # The product must not manufacture a historical receipt gap.
                            require(
                                projection["receipt_status"] == "no_gap"
                                and projection["reconciliation_status"]
                                == ("not_needed" if active_confirmed else "pending"),
                                "handoff_invented_receipt_gap",
                            )
                            if active_confirmed:
                                require(
                                    projection["execution_status"] == "confirmed",
                                    "active_evidence_lost",
                                )
                            else:
                                require(
                                    projection["execution_status"] != "confirmed",
                                    "expired_invented_activation",
                                )
                            text = _download_for_run(
                                page, second.base, settings, prefix, run["run_ref"]
                            )
                            digest = _summary(
                                proof_path.parent,
                                "business-" + phase + ".md",
                                text,
                                settings,
                                host_id,
                                rid,
                            )
                            record["runs"].append(
                                {
                                    "phase": phase,
                                    "run_ref": run["run_ref"],
                                    "historical_verdict": verdict,
                                    "current_verdict": run["current_verdict"],
                                    "checks": projection["checks"],
                                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                                    "summary_sha256": digest,
                                }
                            )
                        require(
                            len({row["run_ref"] for row in record["runs"]}) == 3,
                            "recheck_ref_reused",
                        )
                        historical = OriginalHistory(
                            host_id,
                            rid,
                            tuple(
                                StoredRun(row["run_ref"], row["historical_verdict"])
                                for row in record["runs"]
                            ),
                        )
                        sealed_before = sealed_runs(settings.data_dir, historical)
                        selection = page.locator("[data-defense-recheck=selection]")
                        for old in record["runs"]:
                            if selection.input_value() != old["run_ref"]:
                                with page.expect_response(
                                    lambda response, ref=old["run_ref"]: (
                                        response.request.method == "GET"
                                        and response.url.endswith("/rechecks/" + ref)
                                    )
                                ) as selected:
                                    selection.select_option(old["run_ref"])
                                require(selected.value.status == 200, "old_run_not_selected")
                            expect(selection).to_have_value(old["run_ref"])
                            text = _download_for_run(
                                page, second.base, settings, prefix, old["run_ref"]
                            )
                            label = {
                                "failed": "复验未通过",
                                "pending": "待验收",
                                "passed": "登记业务复验通过",
                            }[old["historical_verdict"]]
                            require(
                                "所选历史复验：" + label in text, "old_historical_verdict_changed"
                            )
                            _summary(
                                proof_path.parent,
                                "history-" + old["phase"] + ".md",
                                text,
                                settings,
                                host_id,
                                rid,
                            )
                        require(not errors, "browser_second_error")
                        require(
                            sealed_runs(settings.data_dir, historical) == sealed_before,
                            "historical_originals_changed",
                        )
                        record["sealed_runs"] = sealed_before
                        record["old_reports_reopened"] = True
                    finally:
                        context.close()
                record["processes"].append(second.audit)
                require(
                    not any(
                        second.audit["write_requests"].get(op, 0)
                        for op in ("arm", "prepare", "apply")
                    ),
                    "restart_replayed_action",
                )
                require(
                    second.audit["write_requests"].get("rechecks") == 3, "recheck_count_changed"
                )
                require(
                    apply_record(settings.data_dir, rid) == original_apply, "final_apply_changed"
                )
                require(
                    immutable_submission(settings.data_dir, rid) == immutable_before,
                    "query_changed_original_submission",
                )
                record["original_submission_unchanged"] = True
                record["native_final"] = snapshot()
                ledger = record["native_final"]["ledger"]
                require(
                    ledger["usage_count"] == ledger["intents"] == 1 and not ledger["kernel_active"],
                    "native_final_not_closed",
                )
                production = all(
                    row["production_root_invoker"] and row["production_business_collector"]
                    for row in record["processes"]
                )
                record["production_root_invoker"] = all(
                    row["production_root_invoker"] for row in record["processes"]
                )
                record["production_business_collector"] = all(
                    row["production_business_collector"] for row in record["processes"]
                )
                record["live_root_reconnect_verified"] = production
                record["ai_dispatches"] = sum(row["model_attempts"] for row in record["processes"])
                require(record["ai_dispatches"] == 0, "model_attempted")
                record["flow_completed"] = True
                record["full_current_acceptance"] = active_confirmed
                record["completed"] = active_confirmed
                record["phase"] = "verified" if active_confirmed else "reconciled_only"
            finally:
                browser.close()
    except Exception as error:
        record["failure_type"] = type(error).__name__
        if isinstance(error, RestartAcceptanceError):
            record["reason_code"] = str(error)
    finally:
        record["processes"] = [
            server.audit for server in (first, second) if server is not None and server.audit
        ]
        record["ai_dispatches"] = sum(row["model_attempts"] for row in record["processes"])
    with proof_path.open("x", encoding="ascii") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")
    return record
