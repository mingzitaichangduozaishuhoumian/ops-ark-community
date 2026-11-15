"""A real background watcher, never an HTTP query substituted for its tick."""

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from browser_defense_abrupt_process_smoke import _summary, _task
from browser_defense_native_smoke import _confirm, _login, _response
from defense_abrupt_process import (
    BOUNDARY,
    EXIT_CODE,
    AbruptProcess,
    immutable_submission,
    uncommitted_apply,
)
from defense_live_process import apply_record
from defense_recheck_process_restart import _read, require
from defense_task_watch_process import WatchProcess
from playwright.sync_api import expect, sync_playwright

from opsark.config import Settings

RESTART_OBSERVE_SECONDS = 31.5
WATCH_WAIT_SECONDS = 100


class WatchReconciledOnly(RuntimeError):
    """An expired first observation cannot prove activation or the manual branch."""


def watch_snapshot(directory: Path, rid: str) -> dict:
    """Small typed operational facts and digests, not original rows or logs."""
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT task_reference_sha256,last_state,terminal,attempts,daily_attempts,charged_day "
            "FROM defense_task_watches_v1 WHERE rid=?",
            (rid,),
        ).fetchone()
        events = db.execute(
            "SELECT sequence,event_ref,state,observed_at,acknowledged_at "
            "FROM defense_task_watch_events_v1 WHERE rid=? ORDER BY sequence",
            (rid,),
        ).fetchall()
        lease = db.execute("SELECT epoch FROM defense_task_watch_lease_v1").fetchone()
        attempts = db.execute(
            "SELECT count(*),COALESCE(sum(finished_at IS NOT NULL),0) "
            "FROM defense_task_watch_attempts_v1 WHERE rid=?",
            (rid,),
        ).fetchone()
    return {
        "task": None if row is None else dict(row),
        "attempt_rows": attempts[0],
        "finished_attempts": attempts[1],
        "lease_epoch": None if lease is None else lease[0],
        "events": [
            {
                "sequence": item["sequence"],
                "event_ref_sha256": hashlib.sha256(item["event_ref"].encode()).hexdigest(),
                "state": item["state"],
                "observed_at": item["observed_at"],
                "acknowledged_at": item["acknowledged_at"],
            }
            for item in events
        ],
    }


def protection_image(directory: Path, rid: str) -> str:
    """ACK cannot release latches, alter accounting, mode or original submission."""
    hasher = hashlib.sha256(immutable_submission(directory, rid).encode())
    for name, queries in (
        ("security.sqlite3", ("SELECT rowid,* FROM defense_target_latches ORDER BY rowid",)),
        (
            "automation.sqlite3",
            ("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name",),
        ),
    ):
        with closing(sqlite3.connect((directory / name).as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            for query in queries:
                rows = db.execute(query).fetchall()
                hasher.update(repr(rows).encode())
                if name == "automation.sqlite3":
                    for table, _ in rows:
                        quoted = '"' + table.replace('"', '""') + '"'
                        data = db.execute(
                            "SELECT rowid,* FROM " + quoted + " ORDER BY rowid"  # noqa: S608 -- quoted owned catalog identifiers only.
                        ).fetchall()
                        hasher.update(repr(data).encode())
    return hasher.hexdigest()


def _get(base, settings, path):
    status, raw, _ = _read(base, settings.token, path)
    require(status == 200, "watch_read_unavailable")
    return json.loads(raw)


def _wait(read, predicate, *, seconds=None):
    seconds = WATCH_WAIT_SECONDS if seconds is None else seconds
    deadline = time.monotonic() + seconds
    while True:
        value = read()
        if predicate(value):
            return value
        require(time.monotonic() < deadline, "watch_observation_timeout")
        time.sleep(0.2)


def _original_stage(browser, settings, processes, stimulate):
    first = AbruptProcess(settings, processes, 1)
    with first:
        host_id = first.ready["host_id"]
        context, page, errors = _login(browser, first.base, settings.token)
        try:
            page.locator("#automation-mode-select").select_option("assisted")
            with _response(page, "/api/automation", method="PUT") as mode:
                page.locator("#save-automation-mode").click()
            require(
                mode.value.status == 200 and mode.value.json()["mode_sync_complete"],
                "mode_unsynced",
            )
            page.locator('button[data-view="security"]').click()
            page.locator('[data-defense="arm"]').click()
            with _response(page, "/ssh-defense/arm") as armed:
                _confirm(page)
            require(armed.value.status == 200, "arm_failed")
            cursor = armed.value.json()["request_id"]
            require(stimulate(cursor)["cursor_request_id"] == cursor, "stimulus_changed")
            with _response(page, "/transactions/" + cursor + "/query") as observed:
                page.get_by_role("button", name="查询同一个原任务", exact=True).click()
            require(observed.value.status == 200, "source_query_failed")
            page.locator('[name="ssh-defense-source"]:enabled').check()
            with _response(page, "/ssh-defense/prepare") as prepared:
                page.get_by_role("button", name="准备处置清单（不执行）", exact=True).click()
            require(prepared.value.status == 200, "prepare_failed")
            action = prepared.value.json()
            rid = action["request_id"]
            page.get_by_role("button", name="核对并执行这份清单", exact=True).click()
            with page.expect_event(
                "requestfailed",
                predicate=lambda request: (
                    request.method == "POST"
                    and request.url.endswith("/transactions/" + rid + "/apply")
                ),
            ) as failed:
                _confirm(page)
            require(failed.value.response() is None and not errors, "apply_was_not_abrupt")
            pending = uncommitted_apply(settings.data_dir, rid)
            require(
                pending["dispatch_phase"] == "sendable"
                and not pending["reply_committed"]
                and pending["apply_observations"] == 0
                and pending["query_required"],
                "unavailable_was_committed",
            )
            original = apply_record(settings.data_dir, rid)
            digest = immutable_submission(settings.data_dir, rid)
        finally:
            context.close()
    marker = first.audit["boundary"]
    require(
        first.audit["actual_exit_code"] == EXIT_CODE
        and marker["boundary"] == BOUNDARY
        and marker["request_ref_sha256"] == hashlib.sha256(rid.encode()).hexdigest()
        and marker["request_sha256"] == original["request_sha256"]
        and first.audit["write_requests"].get("apply") == 1,
        "crash_identity_changed",
    )
    return first, host_id, rid, cursor, action["manifest"]["sha256"], original, digest, pending


def run_task_watch_browser(
    settings: Settings,
    *,
    stimulate_after_arm: Callable[[str], dict],
    snapshot: Callable[[], dict],
    proof_path: Path,
    change_phase=None,
) -> dict:
    """Three real processes; background queries, manual follow-up and durable ACK.

    Business checks are deliberately not run. The exported handoff must remain
    pending. Native socket acceptance still needs the independent operator proof.
    """
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
        "data_not_fresh",
    )
    processes = proof_path.parent / "controller-processes"
    require(not processes.exists(), "process_directory_exists")
    processes.mkdir(mode=0o700)
    record = {
        "schema": "opsark-defense-task-watch-native-browser/v1",
        "completed": False,
        "watch_acceptance_passed": False,
        "business_verdict": "pending",
        "business_recollection": False,
        "resident_modified": False,
        "host_or_container_restart_verified": False,
        "actual_socket_fault_independently_required": True,
        "ai_dispatches": 0,
        "worker_automatic_queries_verified": False,
        "manual_followup_verified": False,
        "processes": [],
        "phase": "starting",
    }
    first = second = third = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                first, host_id, rid, cursor, manifest, original, immutable, pending = (
                    _original_stage(browser, settings, processes, stimulate_after_arm)
                )
                record.update(
                    request_id=rid,
                    cursor_request_id=cursor,
                    manifest_sha256=manifest,
                    original_apply=original,
                    submission_before_sha256=immutable,
                    uncommitted_apply_before_restart=pending,
                    os_exit_boundary_verified=True,
                    actual_process_exit_code=EXIT_CODE,
                    apply_request_failed_without_response=True,
                )
                record["processes"].append(first.audit)
                watched = replace(
                    settings,
                    defense_task_watch_enabled=True,
                    defense_task_watch_host_ids=(host_id,),
                    defense_task_watch_interval_seconds=30,
                )
                prefix = "/api/hosts/" + host_id + "/ssh-defense/transactions/" + rid
                second = WatchProcess(watched, processes, 2)
                with second:
                    require(second.pid != first.pid, "process_pid_reused")
                    record["controller_process_restart_verified"] = True
                    record["phase"] = "background_original_query"
                    seen = _wait(
                        lambda: watch_snapshot(settings.data_dir, rid),
                        lambda value: (
                            value["task"] is not None
                            and value["task"]["last_state"] in {"active", "expired"}
                        ),
                        seconds=40,
                    )
                    first_state = seen["task"]["last_state"]
                    record["first_reconciled_state"] = first_state
                    current = _task(second.base, watched, prefix)
                    require(
                        current["request_id"] == rid
                        and current["manifest"]["sha256"] == manifest
                        and not current["query_required"]
                        and current["current_result"]["state"] == first_state,
                        "worker_did_not_reconcile_original",
                    )
                    record["worker_automatic_queries_verified"] = True
                    if first_state != "active":
                        require(
                            immutable_submission(settings.data_dir, rid) == immutable,
                            "partial_changed_original_submission",
                        )
                        record["original_submission_unchanged"] = True
                        record["phase"] = "reconciled_only"
                        raise WatchReconciledOnly("first_watch_already_expired")
                    context, page, errors = _login(browser, second.base, watched.token)
                    try:
                        page.locator("#automation-mode-select").select_option("manual")
                        with _response(page, "/api/automation", method="PUT") as manual:
                            page.locator("#save-automation-mode").click()
                        require(
                            manual.value.status == 200 and manual.value.json()["mode"] == "manual",
                            "manual_not_saved",
                        )
                        after_manual = watch_snapshot(settings.data_dir, rid)
                        final = _wait(
                            lambda: watch_snapshot(settings.data_dir, rid),
                            lambda value: (
                                value["attempt_rows"] > after_manual["attempt_rows"]
                                and value["task"]["terminal"] == 1
                                and value["task"]["last_state"] == "expired"
                            ),
                        )
                        require(
                            _get(second.base, watched, "/api/automation")["mode"] == "manual",
                            "manual_mode_changed",
                        )
                        record["manual_followup_verified"] = True
                        record["worker_automatic_queries_verified"] = True
                        record["watch_after_expiry"] = final
                        page.locator('button[data-view="security"]').click()
                        with _response(page, "/task-watch/events", method="GET"):
                            page.get_by_role("button", name="刷新跟进告警", exact=True).click()
                        events = _get(second.base, watched, "/api/ssh-defense/task-watch/events")
                        rows = [item for item in events["events"] if item["request_id"] == rid]
                        require(
                            [item["state"] for item in rows] == ["active", "expired"],
                            "event_transition_changed",
                        )
                        reference = rows[0]["event_ref"]
                        protected = protection_image(settings.data_dir, rid)
                        section = page.locator('[data-defense="task-watch"]')
                        article = (
                            section.locator("article")
                            .filter(has_text=rows[0]["task_reference_sha256"])
                            .first
                        )
                        with _response(page, "/events/" + reference + "/ack") as ack:
                            article.get_by_role("button", name="仅标记已阅", exact=True).click()
                        require(
                            ack.value.status == 200 and ack.value.json()["acknowledged_at"],
                            "ack_not_saved",
                        )
                        acknowledged = watch_snapshot(settings.data_dir, rid)
                        require(
                            acknowledged["task"] == final["task"]
                            and acknowledged["attempt_rows"] == final["attempt_rows"]
                            and protection_image(settings.data_dir, rid) == protected,
                            "ack_changed_authority_or_budget",
                        )
                        record["ack_only_confirmed"] = True
                        record["watch_after_ack"] = acknowledged
                        article.get_by_role("button", name="打开对应原任务", exact=True).click()
                        expect(page.locator('[data-defense="detail"]')).to_contain_text(rid)
                        expected_status, expected_raw, _ = _read(
                            second.base, watched.token, prefix + "/handoff"
                        )
                        require(expected_status == 200, "pending_handoff_unavailable")
                        with page.expect_download() as downloaded:
                            page.get_by_role(
                                "button", name="导出未复验摘要（待验收）", exact=True
                            ).click()
                        text = Path(downloaded.value.path()).read_text(encoding="utf-8")
                        require(
                            hashlib.sha256(text.encode()).digest()
                            == hashlib.sha256(expected_raw).digest(),
                            "pending_handoff_wrong_original",
                        )
                        require("当前验收：待验收" in text, "root_status_became_business_pass")
                        record["pending_summary_sha256"] = _summary(
                            proof_path.parent,
                            "watch-business-pending.md",
                            text,
                            settings,
                            host_id,
                            rid,
                        )
                        require(not errors, "watch_browser_error")
                    finally:
                        context.close()
                record["processes"].append(second.audit)
                baseline = watch_snapshot(settings.data_dir, rid)
                third = WatchProcess(watched, processes, 3)
                with third:
                    require(third.pid not in {first.pid, second.pid}, "process_pid_reused")
                    record["phase"] = "terminal_watch_restart"
                    deadline = time.monotonic() + RESTART_OBSERVE_SECONDS
                    while time.monotonic() < deadline:
                        status = _get(third.base, watched, "/api/ssh-defense/task-watch")
                        require(status["enabled"] and status["running"], "watcher_not_running")
                        time.sleep(0.2)
                    restored = watch_snapshot(settings.data_dir, rid)
                    events = _get(third.base, watched, "/api/ssh-defense/task-watch/events")
                    restored_events = [
                        {
                            "sequence": item["sequence"],
                            "event_ref_sha256": hashlib.sha256(
                                item["event_ref"].encode()
                            ).hexdigest(),
                            "state": item["state"],
                            "observed_at": item["observed_at"],
                            "acknowledged_at": item["acknowledged_at"],
                        }
                        for item in events["events"]
                        if item["request_id"] == rid
                    ]
                    require(
                        restored["lease_epoch"] > baseline["lease_epoch"]
                        and restored["task"] == baseline["task"]
                        and restored["events"] == baseline["events"]
                        and restored_events == baseline["events"]
                        and restored["attempt_rows"] == baseline["attempt_rows"]
                        and restored["finished_attempts"] == baseline["finished_attempts"],
                        "restart_repeated_or_reset_followup",
                    )
                    require(
                        _get(third.base, watched, "/api/automation")["mode"] == "manual"
                        and immutable_submission(settings.data_dir, rid) == immutable
                        and apply_record(settings.data_dir, rid) == original,
                        "restart_changed_original_submission",
                    )
                    record["restart_events_and_budgets_preserved"] = True
                    record["watch_after_restart"] = restored
                record["processes"].append(third.audit)
                require(
                    all(
                        not any(
                            row["write_requests"].get(op, 0)
                            for op in ("arm", "prepare", "apply", "query", "revoke", "rechecks")
                        )
                        for row in record["processes"][1:]
                    ),
                    "http_substituted_for_background_query",
                )
                record["native_final"] = snapshot()
                ledger = record["native_final"]["ledger"]
                require(
                    ledger["usage_count"] == ledger["intents"] == 1 and not ledger["kernel_active"],
                    "native_final_not_closed",
                )
                all_processes = record["processes"]
                production = all(
                    row["production_root_invoker"] and row["production_business_collector"]
                    for row in all_processes
                ) and all(row["production_watcher"] for row in all_processes[1:])
                record["production_root_invoker"] = all(
                    row["production_root_invoker"] for row in all_processes
                )
                record["production_business_collector"] = all(
                    row["production_business_collector"] for row in all_processes
                )
                record["controller_process_restart_verified"] = True
                record["live_root_reconnect_verified"] = production
                record["original_submission_unchanged"] = True
                record["ai_dispatches"] = sum(row["model_attempts"] for row in all_processes)
                require(record["ai_dispatches"] == 0, "model_attempted")
                record["watch_acceptance_passed"] = True
                record["completed"] = True
                record["phase"] = "verified"
            finally:
                browser.close()
    except Exception as error:
        record["failure_type"] = type(error).__name__
    finally:
        for process in (first, second, third):
            if (
                process is not None
                and process.audit
                and not any(item["pid"] == process.audit["pid"] for item in record["processes"])
            ):
                record["processes"].append(process.audit)
    with proof_path.open("x", encoding="ascii") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")
    return record
