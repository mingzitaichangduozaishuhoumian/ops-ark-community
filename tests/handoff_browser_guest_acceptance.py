"""Drive the real handoff UI through a loopback tunnel to a read-only lab.

The lab operator prepares each HTTP phase after the driver creates its `.ready`
marker, then creates the matching `.armed` marker. Requests are observed, never
mocked. Only customer-safe Markdown and an aggregate receipt are saved.
"""

import argparse
import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from handoff_guest_acceptance import check, private_fields, prove_log_marker, prove_recheck
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

REPORT_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
DIGEST = re.compile(r"[0-9a-f]{64}")
STATUS_LABELS = {"failed": "复验未通过", "pending": "待验收", "passed": "登记业务复验通过"}
PHASES = (
    ("mixed-failure", "failed", ("passed", "failed", "timeout")),
    ("mixed-pending", "pending", ("passed", "passed", "timeout")),
    ("restored", "passed", ("passed", "passed", "passed")),
)
CHECK_IDS = ("lab", "auxiliary", "third")


def await_fixture(directory, phase, timeout):
    armed = directory / f"{phase}.armed"
    check(not armed.exists(), "phase was armed before its ready marker")
    (directory / f"{phase}.ready").touch(exist_ok=False)
    deadline = time.monotonic() + timeout
    while not armed.is_file():
        check(time.monotonic() < deadline, f"lab did not arm {phase}")
        time.sleep(0.1)


def read_json(api, path, token):
    response = api.get(path, headers={"Authorization": f"Bearer {token}"})
    check(response.ok, "authenticated read of lab evidence failed")
    return response.json()


def report_path(report_id):
    check(isinstance(report_id, str) and REPORT_ID.fullmatch(report_id), "invalid lab report ID")
    return f"/api/reports/{report_id}"


def download_summary(page, request_log, endpoint, job_id, recheck_id):
    count = len(request_log)
    with page.expect_download() as event:
        page.locator("#handoff-download").click()
    saved = event.value
    check(saved.suggested_filename == "opsark-handoff.md", "unexpected download filename")
    check(
        request_log[count:]
        == [(endpoint, {"job_id": [job_id], "recheck_report_id": [recheck_id]})],
        "download did not use the selected original task and report",
    )
    result = Path(saved.path()).read_bytes()
    check(len(result) <= 16_384, "customer Markdown exceeded the evidence budget")
    return result


def verify_summary(content, status, matches, blocked, *, native=False):
    document = content.decode("utf-8")
    check(
        f"复验符合 {matches} / 3 项登记检查。" in document
        and f"**{STATUS_LABELS[status]}。**" in document
        and "独立只读业务复验已记录" in document
        and all(
            f"**{label}。**" not in document
            for key, label in STATUS_LABELS.items()
            if key != status
        ),
        "customer Markdown did not match the selected business result",
    )
    if native:
        check(
            all(
                label in document
                for label in (
                    "人工逐项批准",
                    "补丁任务验证通过",
                    "提交结果未知已记录",
                    "查询原任务已核实结果",
                )
            )
            and "待对账" not in document,
            "customer Markdown did not preserve the reconciled native task history",
        )
    check(
        all(value.casefold() not in document.casefold() for value in blocked)
        and re.search(
            r"\b[0-9a-f]{32,64}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|BEGIN .+ KEY", document, re.I
        )
        is None,
        "customer Markdown contained private content",
    )


def prove_native_receipt(job, args):
    verification = job["verification"]
    version = verification["exact_package_version"]
    rescan = verification["vendor_rescan"]
    fresh_ssh = verification["fresh_ssh"]
    hook = job["hook_receipt"]
    check(
        type(job["schema_version"]) is int
        and job["schema_version"] == 1
        and job["authorization"] == "assisted"
        and type(job["install_exit_code"]) is int
        and job["install_exit_code"] == 0
        and sum(item["status"] == "applying" for item in job["history"]) == 1
        and hook["job_id"] == job["job_id"]
        and DIGEST.fullmatch(hook["expected_sha256"])
        and hook["expected_sha256"] == job["expected_transaction_sha256"]
        and DIGEST.fullmatch(hook["transaction_sha256"])
        and version["passed"] is True
        and version["expected"] == version["observed"] == args.native_expected_version
        and rescan["passed"] is True
        and rescan["finding_id"] == args.native_finding_id
        and re.fullmatch(r"[0-9a-f]{32}", rescan["scan_id"])
        and verification["health"]["passed"] is True
        and fresh_ssh["passed"] is True
        and fresh_ssh["mechanism"] == "sshd_connection_started_after_local_verification"
        and datetime.fromisoformat(job["locally_verified_at"])
        <= datetime.fromisoformat(fresh_ssh["checked_at"])
        <= datetime.fromisoformat(job["completed_at"]),
        "cached native receipt did not prove the approved transaction, rescan and fresh SSH",
    )
    return {
        args.native_expected_version,
        args.native_finding_id,
        rescan["scan_id"],
        hook["transaction_sha256"],
    }


def run(browser, args, token):
    context = browser.new_context(base_url=args.url, accept_downloads=True, service_workers="block")
    context.set_default_timeout(args.timeout * 1000)
    try:
        exercise(context, args, token)
    finally:
        context.close()


def exercise(context, args, token):
    api = context.request
    capabilities = read_json(api, "/api/capabilities", token)
    remediation = read_json(api, "/api/remediation", token)
    check(
        capabilities["handoff_recheck"] is True
        and capabilities["model_configured"] is False
        and remediation["configured"] is False
        and remediation["execution_available"] is False
        and not remediation["hosts"]
        and not remediation["supported_execution_modes"]
        and len(remediation["jobs"]) == 1,
        "requires a read-only isolated controller with one cached task",
    )
    job = remediation["jobs"][0]
    check(
        job["job_id"] == args.job_id
        and job["status"] == "verified"
        and job["evidence_origin"] == "controlled_lab",
        "the original task is not a verified lab task",
    )
    hosts = read_json(api, "/api/hosts", token)
    check(
        [host["id"] for host in hosts if host["source"] == "ssh"] == [job["host_id"]],
        "requires exactly one isolated SSH target",
    )
    reports = read_json(api, "/api/reports", token)
    check(bool(reports), "the original investigation is missing")
    if args.require_native_receipt:
        check(len(reports) == 1, "native verification requires only the original investigation")
    original_path = report_path(reports[0]["id"])
    original = read_json(api, original_path, token)
    configs = {item["id"]: item for item in original["target"]["health_checks"]}
    check(
        original["source"] == "ssh"
        and original["host_id"] == job["host_id"]
        and configs.keys() == set(CHECK_IDS)
        and all(item["read_only_confirmed"] for item in configs.values()),
        "original report lacks three confirmed business checks for this target",
    )
    prove_log_marker(original, args.log_marker)
    blocked = private_fields(original) | {
        token,
        args.job_id,
        args.log_marker,
        args.wrong_body_marker,
        "Operation timed out",
        "Timeout was reached",
        *args.private_marker,
    }
    blocked.update(
        job[key]
        for key in ("plan_id", "plan_digest", "policy_digest", "execution_policy_digest")
        if isinstance(job.get(key), str) and job[key]
    )
    if args.require_native_receipt:
        blocked.update(prove_native_receipt(job, args))
    page = context.new_page()
    page_errors, mutations, exports, downloads = [], [], [], []
    page.on("pageerror", lambda _: page_errors.append(True))
    page.on("download", lambda _: downloads.append(True))

    def record(request):
        url = urlsplit(request.url)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            mutations.append((url.path, request.method, request.post_data_json))
        if url.path.endswith("/handoff"):
            exports.append((url.path, parse_qs(url.query)))

    page.on("request", record)
    page.goto(args.url, wait_until="networkidle")
    page.locator("#token-input").fill(token)
    page.locator("#login-button").click()
    expect(page.locator("#report-id")).to_have_text(original["id"])
    dialog = page.locator("#handoff-dialog")
    run_recheck = page.locator("#handoff-run-recheck")
    select_recheck = page.locator("#handoff-recheck")
    result = page.locator("#handoff-recheck-result")
    recheck_endpoint = original_path + "/handoff-rechecks"
    export_endpoint = original_path + "/handoff"

    def open_handoff():
        page.locator("#export-handoff").click()
        expect(dialog).to_be_visible()
        page.locator("#handoff-job").select_option(args.job_id)
        expect(run_recheck).to_be_enabled()

    collected_after = max(
        datetime.fromisoformat(value)
        for value in (original["created_at"], job["updated_at"], job["received_at"])
    )
    documents = {}
    for index, (phase, status, outcomes) in enumerate(PHASES, 1):
        open_handoff()
        await_fixture(args.barrier_dir, phase, args.timeout)
        prior_download_count = len(downloads)
        with page.expect_response(
            lambda response: (
                urlsplit(response.url).path == recheck_endpoint
                and response.request.method == "POST"
            )
        ) as response:
            run_recheck.click()
        check(response.value.status == 201, f"live browser recheck request failed in {phase}")
        row = response.value.json()
        matches = outcomes.count("passed")
        check(
            set(row) == {"id", "at", "status", "configured_checks", "matched_checks"}
            and row["status"] == status
            and row["configured_checks"] == 3
            and row["matched_checks"] == matches,
            f"unexpected aggregate response in {phase}",
        )
        report = read_json(api, report_path(row["id"]), token)
        check(
            report["id"] != original["id"]
            and report["source"] == "ssh"
            and report["scenario"] == original["scenario"]
            and report["host_id"] == original["host_id"]
            and report["scope_hash"] == original["scope_hash"]
            and report["target"]["health_checks"] == original["target"]["health_checks"]
            and datetime.fromisoformat(report["created_at"]) == datetime.fromisoformat(row["at"]),
            f"business evidence lost its original SSH scope in {phase}",
        )
        for check_id, outcome in zip(CHECK_IDS, outcomes, strict=True):
            prove_recheck(
                report, configs[check_id], outcome, args.wrong_body_marker, collected_after
            )
        prove_log_marker(report, args.log_marker)
        collected_after = datetime.fromisoformat(report["created_at"])
        blocked.update(private_fields(report))
        expect(select_recheck).to_have_value(row["id"])
        expect(result).to_contain_text(STATUS_LABELS[status])
        expect(result).to_contain_text(f"{matches}/3")
        check(len(downloads) == prior_download_count, "recheck automatically downloaded Markdown")
        check(
            mutations == [(recheck_endpoint, "POST", {"job_id": args.job_id})] * index,
            "browser made an unexpected mutation or duplicate recheck",
        )
        document = download_summary(page, exports, export_endpoint, args.job_id, row["id"])
        verify_summary(document, status, matches, blocked, native=args.require_native_receipt)
        documents[phase] = (report, document, status, matches)
        expect(dialog).to_be_hidden()
        print(f"{phase}: browser and live SSH evidence agreed ({matches}/3)", flush=True)

    for phase, _, _ in PHASES[:2]:
        report, document, status, matches = documents[phase]
        open_handoff()
        select_recheck.select_option(report["id"])
        expect(result).to_contain_text(STATUS_LABELS[status])
        expect(result).to_contain_text(f"{matches}/3")
        check(
            read_json(api, report_path(report["id"]), token) == report
            and download_summary(page, exports, export_endpoint, args.job_id, report["id"])
            == document,
            f"older {phase} report or customer Markdown changed after restoration",
        )
        expect(dialog).to_be_hidden()
    check(
        mutations == [(recheck_endpoint, "POST", {"job_id": args.job_id})] * 3
        and len(exports) == len(downloads) == 5
        and not page_errors
        and read_json(api, original_path, token) == original
        and read_json(api, "/api/remediation", token)["jobs"] == [job],
        "browser acceptance did not preserve the original records or request boundaries",
    )
    receipt = {
        "browser": "chromium",
        "ssh_rechecks": len(mutations),
        "remediation_mutations": 0,
        "original_job_preserved": True,
        "older_downloads_byte_identical": 2,
        "results": [],
    }
    if args.require_native_receipt:
        receipt["native_receipt_verified"] = True
    for phase, (_, document, status, matches) in documents.items():
        verify_summary(document, status, matches, blocked, native=args.require_native_receipt)
        filename = f"{phase}.md"
        (args.out_dir / filename).write_bytes(document)
        receipt["results"].append(
            {
                "phase": phase,
                "status": status,
                "matched": matches,
                "configured": 3,
                "file": filename,
                "sha256": hashlib.sha256(document).hexdigest(),
            }
        )
    (args.out_dir / "acceptance.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument(
        "--require-native-receipt", action="store_true", help="require a real verified lab receipt"
    )
    parser.add_argument(
        "--native-expected-version", help="exact version approved before installation"
    )
    parser.add_argument("--native-finding-id", help="finding ID from the pre-installation scan")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--barrier-dir", type=Path, required=True)
    parser.add_argument("--private-marker", action="append", default=[])
    parser.add_argument("--log-marker", default="OPSARK_HANDOFF_RAW_LOG_ECHO")
    parser.add_argument("--wrong-body-marker", default="OPSARK_HANDOFF_WRONG_BODY")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    try:
        url = urlsplit(args.url)
        check(
            url.scheme == "http"
            and url.hostname == "127.0.0.1"
            and url.port is not None
            and url.path in {"", "/"}
            and not (url.username or url.password or url.query or url.fragment)
            and re.fullmatch(r"[0-9a-f]{32}", args.job_id)
            and args.timeout > 0
            and args.barrier_dir.is_dir()
            and not any(args.barrier_dir.iterdir())
            and args.log_marker
            and args.wrong_body_marker
            and all(args.private_marker),
            "invalid loopback lab address, task, timeout, markers or barrier directory",
        )
        if args.require_native_receipt:
            check(
                args.native_expected_version
                and re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,127}", args.native_expected_version)
                and args.native_finding_id
                and DIGEST.fullmatch(args.native_finding_id),
                "native receipt verification needs the approved package version and finding ID",
            )
        else:
            check(
                args.native_expected_version is None and args.native_finding_id is None,
                "native receipt inputs require --require-native-receipt",
            )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        check(not any(args.out_dir.iterdir()), "output directory is not empty")
        token = args.token_file.read_text(encoding="utf-8").strip()
        check(len(token) >= 16, "test token file is empty or too short")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                run(browser, args, token)
            finally:
                browser.close()
    except RuntimeError as error:
        parser.exit(1, f"Browser acceptance failed: {error}\n")
    except (AssertionError, PlaywrightError, KeyError, TypeError, ValueError, OSError):
        parser.exit(1, "Browser acceptance failed during a protected UI or evidence check.\n")


if __name__ == "__main__":
    main()
