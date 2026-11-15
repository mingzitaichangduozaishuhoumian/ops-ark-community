"""Real application business-recheck acceptance over operator-supplied owned transports.

The fixture adapter only changes three fixed HTTP phases and produces five test
authentication failures. It cannot supply a business result to the application.
"""

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path

import httpx
from browser_defense_native_smoke import _confirm, _environment, _login, _response, _serve
from playwright.sync_api import sync_playwright

from opsark.business_readiness import run_business_readiness
from opsark.config import Settings
from opsark.defense_client import invoke
from opsark.defense_models import utc


class BusinessAcceptanceError(RuntimeError):
    pass


def require(condition):
    if not condition:
        raise BusinessAcceptanceError("The bound business acceptance phase did not confirm.")


def save_summary(proof_path, filename, text):
    path = proof_path.parent / filename
    with path.open("x", encoding="utf-8") as output:
        output.write(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def download(page, button_name):
    with page.expect_download() as received:
        page.get_by_role("button", name=button_name, exact=True).click()
    item = received.value
    require(item.suggested_filename == "opsark-defense-handoff.md")
    return Path(item.path()).read_text(encoding="utf-8")


def run_business_browser(
    settings: Settings,
    *,
    stimulate_after_arm: Callable[[str], dict],
    change_phase: Callable[[str], dict],
    snapshot: Callable[[], dict],
    proof_path: Path,
) -> dict:
    """One action, three real collector runs and an application-instance rebuild."""
    require(not proof_path.exists() and proof_path.is_absolute())
    require(
        settings.data_dir.is_absolute()
        and settings.data_dir.parent.is_dir()
        and not settings.data_dir.is_symlink()
        and not settings.data_dir.is_junction()
        and (not settings.data_dir.exists() or not any(settings.data_dir.iterdir()))
    )
    require(
        settings.ai_base_url is None
        and settings.ai_key is None
        and settings.ai_key_file is None
        and settings.ai_model is None
        and not settings.defense_worker_enabled
        and not settings.observation_enabled
        and not settings.vulnerability_scan_enabled
    )
    record = {
        "schema": "opsark-defense-business-browser/v1",
        "completed": False,
        "phase": "starting",
        "ai_dispatches": 0,
        "resident_modified": False,
        "host_or_python_process_restart_verified": False,
        "runs": [],
    }
    forbidden_model_attempts = []
    original_send = httpx.AsyncClient.send

    async def no_model_request(*_args, **_kwargs):
        forbidden_model_attempts.append(True)
        raise BusinessAcceptanceError("This business acceptance must not contact a model.")

    httpx.AsyncClient.send = no_model_request
    try:
        with _environment(settings.data_dir, settings.token) as create_app:
            app = create_app(settings)
            controller = app.state.defense_service
            rechecks = app.state.defense_recheck_service
            require(len(controller.targets) == 1)
            target = next(iter(controller.targets.values()))
            host_id = target.host.public.id
            record["production_root_invoker"] = controller.invoker is invoke
            record["production_business_collector"] = rechecks.collector is run_business_readiness
            require(not app.state.patch_service.targets and not controller.policy.ai.requires_ai)
            require(len(target.host.business_checks) == 3)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    with _serve(app) as base:
                        context, page, errors = _login(browser, base, settings.token)
                        try:
                            record["phase"] = "original_action"
                            page.locator("#automation-mode-select").select_option("assisted")
                            with _response(page, "/api/automation", method="PUT") as mode:
                                page.locator("#save-automation-mode").click()
                            require(
                                mode.value.status == 200 and mode.value.json()["mode_sync_complete"]
                            )
                            page.locator('button[data-view="security"]').click()
                            page.locator('[data-defense="arm"]').click()
                            with _response(page, "/ssh-defense/arm") as arm:
                                _confirm(page)
                            require(arm.value.status == 200)
                            cursor = arm.value.json()["request_id"]
                            require(stimulate_after_arm(cursor)["cursor_request_id"] == cursor)
                            with _response(page, "/transactions/" + cursor + "/query") as observed:
                                page.get_by_role(
                                    "button", name="查询同一个原任务", exact=True
                                ).click()
                            require(observed.value.status == 200)
                            page.locator('[name="ssh-defense-source"]:enabled').check()
                            with _response(page, "/ssh-defense/prepare") as prepared:
                                page.get_by_role(
                                    "button", name="准备处置清单（不执行）", exact=True
                                ).click()
                            require(prepared.value.status == 200)
                            action = prepared.value.json()
                            rid = action["request_id"]
                            record.update(request_id=rid, cursor_request_id=cursor)
                            record["manifest_sha256"] = action["manifest"]["sha256"]
                            page.get_by_role(
                                "button", name="核对并执行这份清单", exact=True
                            ).click()
                            with _response(page, "/transactions/" + rid + "/apply") as applied:
                                _confirm(page)
                            require(applied.value.status == 503)
                            with _response(page, "/transactions/" + rid + "/query") as queried:
                                page.get_by_role(
                                    "button", name="查询同一个原任务", exact=True
                                ).click()
                            require(queried.value.status == 200)
                            require(queried.value.json()["current_result"]["state"] == "active")
                            page.get_by_role("button", name="核对并撤销原动作", exact=True).click()
                            with _response(page, "/transactions/" + rid + "/revoke") as revoked:
                                _confirm(page)
                            require(revoked.value.status == 200)
                            require(revoked.value.json()["current_result"]["state"] == "revoked")
                            page.locator("#automation-mode-select").select_option("manual")
                            with _response(page, "/api/automation", method="PUT") as manual:
                                page.locator("#save-automation-mode").click()
                            require(manual.value.status == 200)
                            require(manual.value.json()["mode"] == "manual")
                            page.get_by_role("button", name="刷新只读复验历史", exact=True).click()
                            with page.expect_download() as pending_download:
                                page.get_by_role(
                                    "button", name="导出未复验摘要（待验收）", exact=True
                                ).click()
                            pending = Path(pending_download.value.path()).read_text(
                                encoding="utf-8"
                            )
                            require("待验收" in pending)
                            record["before_recheck_summary_sha256"] = save_summary(
                                proof_path, "business-before.md", pending
                            )
                            for phase, expected in (
                                ("mixed", "failed"),
                                ("timeout_only", "pending"),
                                ("restored", "passed"),
                            ):
                                record["phase"] = phase
                                require(type(change_phase(phase)) is dict)
                                page.get_by_role("button", name="运行只读复验", exact=True).click()
                                started = time.monotonic()
                                with _response(
                                    page, "/transactions/" + rid + "/rechecks"
                                ) as checked:
                                    _confirm(page)
                                require(checked.value.status == 200)
                                run = checked.value.json()
                                require(
                                    run["request_id"] == rid
                                    and run["historical_verdict"] == expected
                                )
                                require(run["status"] == "completed")
                                text = download(page, "导出所选复验的安全摘要")
                                label = {
                                    "failed": "复验未通过",
                                    "pending": "待验收",
                                    "passed": "登记业务复验通过",
                                }[expected]
                                require("所选历史复验：" + label in text)
                                require("当前验收：" + label in text)
                                for private in (
                                    settings.token,
                                    host_id,
                                    rid,
                                    "198.18.241.",
                                    "key_file",
                                    "source_ref",
                                    "business.opsark.invalid",
                                ):
                                    require(private not in text)
                                record["runs"].append(
                                    {
                                        "phase": phase,
                                        "run_ref": run["run_ref"],
                                        "historical_verdict": run["historical_verdict"],
                                        "current_verdict": run["current_verdict"],
                                        "checks": run["projection"]["checks"],
                                        "elapsed_ms": round((time.monotonic() - started) * 1000),
                                        "summary_sha256": save_summary(
                                            proof_path, "business-" + phase + ".md", text
                                        ),
                                    }
                                )
                            require(len({r["run_ref"] for r in record["runs"]}) == 3)
                            require(not errors)
                        finally:
                            context.close()
                    require(controller.stopped.is_set())
                    record["first_application_stopped"] = True
                    rebuilt = create_app(settings)
                    with _serve(rebuilt) as base:
                        context, page, errors = _login(browser, base, settings.token)
                        try:
                            page.locator('button[data-view="security"]').click()
                            history = page.locator('[data-defense="history"]')
                            history.get_by_role("button").filter(has_text=rid).click()
                            select = page.locator("[data-defense-recheck=selection]")
                            for old, expected in zip(
                                record["runs"], ("failed", "pending", "passed"), strict=True
                            ):
                                select.select_option(old["run_ref"])
                                text = download(page, "导出所选复验的安全摘要")
                                label = {
                                    "failed": "复验未通过",
                                    "pending": "待验收",
                                    "passed": "登记业务复验通过",
                                }[expected]
                                require(
                                    "所选历史复验：" + label in text
                                    and old["historical_verdict"] == expected
                                )
                                save_summary(proof_path, "history-" + old["phase"] + ".md", text)
                            require(not errors)
                            record["old_reports_reopened_after_application_rebuild"] = True
                        finally:
                            context.close()
                    record["same_python_new_application_instances"] = 2
                    record["native_final"] = snapshot()
                    require(record["native_final"]["ledger"]["usage_count"] == 1)
                    require(record["native_final"]["ledger"]["intents"] == 1)
                    require(not record["native_final"]["ledger"]["kernel_active"])
                    require(
                        len(controller.store.request_metadata(rid, "apply").request_sha256) == 64
                    )
                    require(
                        all(
                            utc(run.finished_at) >= utc(run.started_at)
                            for run in (
                                rebuilt.state.defense_recheck_store.get(item["run_ref"]).result
                                for item in record["runs"]
                            )
                            if run is not None
                        )
                    )
                    record["completed"] = True
                    record["phase"] = "verified"
                finally:
                    browser.close()
    except Exception as error:
        record["failure_type"] = type(error).__name__
    finally:
        httpx.AsyncClient.send = original_send
        record["ai_dispatches"] = len(forbidden_model_attempts)
    with proof_path.open("x", encoding="ascii") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")
    return record
