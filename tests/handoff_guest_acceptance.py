"""Run a customer handoff in an isolated lab, with or without native patch execution."""

import argparse
import hashlib
import json
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

PATCH = "/api/remediation"
INVESTIGATIONS = "/api/investigations"
PENDING = "**待验收。**"
FAILED = "**复验未通过。**"
PASSED = "**登记业务复验通过。**"
RECONCILED = "查询原任务已核实结果"
ACTIVE = {
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "awaiting_transport_verification",
    "running_overdue",
}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(client, label, method, path, *, status=200, **kwargs):
    try:
        response = client.request(method, path, **kwargs)
    except httpx.HTTPError:
        raise RuntimeError(f"{label}: controller connection failed") from None
    check(response.status_code == status, f"{label}: unexpected HTTP {response.status_code}")
    return response


def investigate(client, host_id):
    report = call(
        client,
        "real SSH investigation",
        "POST",
        INVESTIGATIONS,
        json={"host_id": host_id, "source": "ssh", "scenario": "web_502"},
    ).json()
    check(
        report["source"] == "ssh"
        and report["host_id"] == host_id
        and report["scenario"] == "web_502"
        and report["compatibility"]["status"] == "compatible"
        and re.fullmatch(r"[0-9a-f]{64}", report["scope_hash"]),
        "investigation did not cover the registered SSH scope",
    )
    return report


def prove_http(report, marker):
    checks = report["target"]["health_checks"]
    check(
        checks and any(item["expected_body"] == marker for item in checks),
        "the synthetic body is not registered in the live HTTP checks",
    )
    for item in checks:
        name = "http_" + item["id"]
        evidence = [e for e in report["evidence"] if e["check_id"] == name]
        check(
            item["read_only_confirmed"]
            and len(evidence) == 1
            and evidence[0]["status"] == "ok"
            and evidence[0]["source"] == "ssh"
            and evidence[0]["exit_code"] == 0
            and not evidence[0]["truncated"],
            "real HTTP evidence was missing or incomplete",
        )
        if item["expected_body"] == marker:
            check(marker in evidence[0]["output"], "HTTP body marker absent from internal evidence")
        matching = [r for r in report["verification"] if r["evidence_ids"] == [evidence[0]["id"]]]
        check(
            len(matching) == 1
            and matching[0]["status"] == "passed"
            and matching[0]["http_status"] == item["expected_status"]
            and matching[0]["status_matches"] is True
            and matching[0]["body_matches"] is True,
            "registered HTTP status and body did not pass",
        )
    return len(checks)


def export(client, endpoint, job_id, blocked, *, recheck=None):
    params = {"job_id": job_id}
    if recheck is not None:
        params["recheck_report_id"] = recheck
    response = call(client, "handoff export", "GET", endpoint, params=params)
    check(
        response.headers.get("content-disposition") == 'attachment; filename="opsark-handoff.md"'
        and response.headers.get("cache-control") == "no-store"
        and response.headers.get("content-type", "").startswith("text/markdown"),
        "the customer response is not a non-cacheable Markdown attachment",
    )
    output = response.text
    check("# OpsArk 客户交接摘要" in output, "customer report title missing")
    for value in blocked:
        check(value.casefold() not in output.casefold(), "private marker found in customer summary")
    check(
        re.search(r"\b[0-9a-f]{32,64}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|BEGIN .+ KEY", output, re.I)
        is None,
        "internal identifier, address, or key format found in customer summary",
    )
    return output


def private_fields(report):
    target = report["target"]
    values = [report["id"], report["scope_hash"]]
    values.extend(
        target.get(key)
        for key in (
            "id",
            "name",
            "address",
            "username",
            "site_domain",
            "container_name",
            "nginx_config_path",
            "trusted_hosts_digest",
        )
    )
    for item in target["health_checks"]:
        values.extend((item["id"], item["domain"], item["path"], item["expected_body"]))
    return {item for item in values if isinstance(item, str) and len(item) >= 5}


def original_job(client, host_id, job_id, plan_id, timeout):
    deadline = time.monotonic() + timeout
    queries = 0
    while time.monotonic() < deadline:
        try:
            response = client.get(f"{PATCH}/jobs/{host_id}/{job_id}", timeout=20)
        except httpx.HTTPError:
            response = None
        queries += 1
        if response is not None and response.status_code == 200:
            job = response.json()
            check(
                (job["host_id"], job["job_id"], job["plan_id"]) == (host_id, job_id, plan_id),
                "original task query returned a different identity",
            )
            if job["status"] == "verified":
                return job, queries
            check(job["status"] in ACTIVE, "original task reached a nonverified state")
        else:
            check(
                response is None or response.status_code == 503,
                "unexpected HTTP response when querying the original task",
            )
        time.sleep(2)
    raise RuntimeError("original task did not reach verified within the deadline")


def wait_for_submit_barrier(directory, job_id):
    armed = directory / "armed"
    check(directory.is_dir() and not armed.exists(), "submit barrier directory is not fresh")
    prepared = directory / "ready.tmp"
    save(directory, prepared.name, job_id + "\n")
    try:
        (directory / "ready").hardlink_to(prepared)
    finally:
        prepared.unlink()
    deadline = time.monotonic() + 30
    while not armed.is_file():
        check(time.monotonic() < deadline, "SSH fault injector did not arm before approval")
        time.sleep(0.1)


def prove_recheck(report, config, outcome, failed_marker, collected_after):
    check_id = "http_" + config["id"]
    evidence_id = "E-" + check_id.replace("_", "-").upper()
    evidence = [item for item in report["evidence"] if item["check_id"] == check_id]
    results = [item for item in report["verification"] if item["evidence_ids"] == [evidence_id]]
    check(
        config["read_only_confirmed"] and len(evidence) == len(results) == 1,
        "recheck lacked unique evidence for a registered read-only check",
    )
    item, result = evidence[0], results[0]
    check(
        item["id"] == evidence_id
        and item["target"] == report["host_id"]
        and item["source"] == "ssh"
        and not item["truncated"]
        and collected_after
        < datetime.fromisoformat(item["collected_at"])
        <= datetime.fromisoformat(report["created_at"]),
        "recheck lacked fresh bounded evidence for the registered SSH check",
    )
    if outcome == "timeout":
        check(
            item["status"] == "timeout"
            and item["exit_code"] == 28
            and result["status"] == "error"
            and all(
                result[key] is None for key in ("http_status", "status_matches", "body_matches")
            ),
            "recheck did not prove curl timed out without HTTP verification metadata",
        )
        return

    passed = outcome == "passed"
    expected_body = config["expected_body"]
    check(
        item["status"] == "ok"
        and item["exit_code"] == 0
        and result["http_status"] == 200
        and result["status_matches"] is True
        and result["body_matches"] is passed
        and result["status"] == outcome
        and (expected_body in item["output"]) is passed
        and (passed or failed_marker in item["output"]),
        "recheck did not prove the requested HTTP 200 body result",
    )


def exercise_rechecks(client, args, endpoint, job_id, baseline, blocked):
    mixed = args.mixed_recheck_barrier_dir is not None
    directory = args.mixed_recheck_barrier_dir if mixed else args.negative_recheck_barrier_dir
    failed_marker = args.failed_body_marker
    check(directory is not None and failed_marker is not None, "negative recheck is not configured")
    configs = baseline["target"]["health_checks"]
    if mixed:
        cases = (
            (
                "mixed-failure",
                FAILED,
                "04-mixed-recheck-failed.md",
                {"lab": "passed", "auxiliary": "failed", "third": "timeout"},
            ),
            (
                "mixed-pending",
                PENDING,
                "05-mixed-recheck-pending.md",
                {"lab": "passed", "auxiliary": "passed", "third": "timeout"},
            ),
            (
                "restored",
                PASSED,
                "06-restored-recheck-passed.md",
                {config["id"]: "passed" for config in configs},
            ),
        )
    else:
        check_id = configs[0]["id"]
        cases = (
            ("mismatch", FAILED, "04-business-recheck-failed.md", {check_id: "failed"}),
            ("timeout", PENDING, "05-business-recheck-timeout.md", {check_id: "timeout"}),
        )
    blocked.update((failed_marker, "Operation timed out", "Timeout was reached"))
    previous = baseline
    artifacts = {}
    history = {}
    for phase, expected_label, filename, outcomes in cases:
        armed = directory / f"{phase}.armed"
        check(not armed.exists(), "recheck barrier is not fresh")
        save(directory, f"{phase}.ready", "")
        deadline = time.monotonic() + 30
        while not armed.is_file():
            check(time.monotonic() < deadline, "recheck fixture was not ready in time")
            time.sleep(0.1)
        report = investigate(client, args.host_id)
        collected_after = datetime.fromisoformat(previous["created_at"])
        check(
            report["id"] != baseline["id"]
            and all(report["id"] != saved["id"] for saved in history.values())
            and report["scope_hash"] == baseline["scope_hash"]
            and report["target"]["health_checks"] == configs
            and datetime.fromisoformat(report["created_at"]) > collected_after,
            "recheck was not collected later in the same registered scope",
        )
        for config in configs:
            prove_recheck(report, config, outcomes[config["id"]], failed_marker, collected_after)
        matched = sum(outcome == "passed" for outcome in outcomes.values())
        blocked.update(private_fields(report))
        document = export(client, endpoint, job_id, blocked, recheck=report["id"])
        check(
            all(
                label in document
                for label in (
                    "人工逐项批准",
                    "补丁任务验证通过",
                    RECONCILED,
                    "独立只读业务复验已记录",
                    expected_label,
                    f"复验符合 {matched} / {len(configs)} 项登记检查",
                )
            )
            and all(label not in document for label in {FAILED, PENDING, PASSED} - {expected_label})
            and "待对账" not in document,
            "customer summary did not reflect the newly collected business evidence",
        )
        save(args.out_dir, filename, document)
        artifacts[phase] = document
        history[phase] = report
        previous = report
    if mixed:
        options = call(
            client, "handoff choices after recovery", "GET", endpoint + "-options"
        ).json()
        selectable = {item["id"] for item in options["rechecks"]}
        check(
            any(item["id"] == job_id for item in options["jobs"])
            and {saved["id"] for saved in history.values()} <= selectable,
            "restoring the checks removed a previous recheck from the handoff choices",
        )
        for phase in ("mixed-failure", "mixed-pending"):
            saved = history[phase]
            report_id = saved["id"]
            detail = call(client, "historical report detail", "GET", f"/api/reports/{report_id}")
            check(detail.json() == saved, "restoring the checks rewrote a previous report")
            check(
                export(client, endpoint, job_id, blocked, recheck=report_id) == artifacts[phase],
                "restoring the checks changed a previous handoff export",
            )
        print("Restored checks passed and both historical reports remained selectable", flush=True)
    print(
        "Failure and actual curl timeout produced distinct, privacy-checked summaries", flush=True
    )
    return artifacts


def registered_ledger(client, args):
    capabilities = call(client, "capabilities", "GET", "/api/capabilities").json()
    hosts = call(client, "registered hosts", "GET", "/api/hosts").json()
    remediation = call(client, "cached remediation store", "GET", PATCH).json()
    check(
        capabilities["handoff_timeline"] is True
        and capabilities["model_configured"] is False
        and [host["id"] for host in hosts if host["source"] == "ssh"] == [args.host_id]
        and "automatic" not in remediation["supported_execution_modes"],
        "controller must be single-target and isolated from external models",
    )
    if args.existing_report_id is not None:
        check(
            remediation["configured"] is False
            and remediation["execution_available"] is False
            and remediation["hosts"] == []
            and remediation["supported_execution_modes"] == [],
            "cached task reuse requires repair to be disabled in the lab",
        )
    else:
        check(
            [host["host_id"] for host in remediation["hosts"]] == [args.host_id],
            "native patch execution must be limited to the same isolated host",
        )
    return remediation["jobs"]


def prove_mixed_registration(report, args):
    configs = {item["id"]: item for item in report["target"]["health_checks"]}
    check(
        len(report["target"]["health_checks"]) == 3
        and configs.keys() == {"lab", "auxiliary", "third"}
        and configs["lab"]["expected_body"] == args.body_marker
        and all(
            item["read_only_confirmed"]
            and item["expected_status"] == 200
            and len(item["expected_body"]) >= 8
            and item["expected_body"] not in args.failed_body_marker
            for item in configs.values()
        ),
        "mixed recheck requires three registered HTTP 200 checks with valid body markers",
    )


def prove_log_marker(report, marker):
    check(
        any(
            entry["check_id"] == "nginx_errors"
            and entry["status"] == "ok"
            and marker in entry["output"]
            for entry in report["evidence"]
        ),
        "synthetic log marker did not reach internal Nginx evidence",
    )


def run(client, args, token):
    jobs = registered_ledger(client, args)
    if args.existing_report_id is not None:
        run_existing(client, args, token, jobs)
        return
    check(not jobs, "controller must have a fresh remediation store before installation")

    original = investigate(client, args.host_id)
    configured = prove_http(original, args.body_marker)
    mixed = args.mixed_recheck_barrier_dir is not None
    if args.negative_recheck_barrier_dir is not None:
        check(
            configured == 1 and original["target"]["health_checks"][0]["expected_status"] == 200,
            "negative recheck requires a single registered HTTP 200 check",
        )
    if mixed:
        prove_mixed_registration(original, args)
    prove_log_marker(original, args.log_marker)
    endpoint = f"/api/reports/{original['id']}/handoff"
    anonymous = httpx.get(client.base_url.join(endpoint), trust_env=False, timeout=15)
    check(anonymous.status_code == 401, "customer export admitted an unauthenticated request")
    print("Original SSH investigation and private markers confirmed", flush=True)

    mode = call(client, "mode", "GET", "/api/automation").json()
    check(mode["mode"] in {"manual", "assisted"}, "isolated mode is not manual or assisted")
    if mode["mode"] == "manual":
        mode = call(
            client,
            "isolated assisted mode",
            "PUT",
            "/api/automation",
            json={"mode": "assisted", "expected_revision": mode["revision"]},
        ).json()
    check(
        mode["mode"] == "assisted" and mode["mode_sync_complete"] is True,
        "assisted approval mode did not synchronize",
    )

    scan = call(
        client, "original APT scan", "POST", f"{PATCH}/scans", json={"host_id": args.host_id}
    ).json()
    findings = [
        item
        for item in scan["findings"]
        if item["package"] == args.package
        and item["current_version"] == args.expected_before
        and item["affected"] is True
        and item["candidate_fixable"] is True
        and item["vendor_evidence_fresh"] is True
        and item["advisory"].startswith("USN-")
        and (args.advisory is None or item["advisory"] == args.advisory)
    ]
    check(findings, "fresh vendor evidence did not confirm the intended vulnerable package")
    finding_id = findings[0]["finding_id"]
    plan = call(
        client,
        "exact patch preview",
        "POST",
        f"{PATCH}/plans",
        json={"host_id": args.host_id, "finding_id": finding_id},
    ).json()
    changes = plan["package_changes"]
    check(
        plan["evidence_origin"] == "controlled_lab"
        and len(changes) == 1
        and changes[0]["name"] == args.package
        and changes[0]["current_version"] == args.expected_before
        and changes[0]["candidate_version"] == args.expected_after
        and plan["finding"]["finding_id"] == finding_id
        and plan["mode_revision"] == mode["revision"]
        and plan["requires_reboot"] is False,
        "patch preview does not match the authorized single-package transition",
    )

    job_id = args.job_id or secrets.token_hex(16)
    blocked = private_fields(original) | {
        token,
        job_id,
        plan["plan_id"],
        plan["plan_digest"],
        plan["policy_digest"],
        finding_id,
        scan["scan_id"],
        args.log_marker,
        args.body_marker,
        *args.private_marker,
    }
    payload = {
        "host_id": args.host_id,
        "job_id": job_id,
        "plan_id": plan["plan_id"],
        "expected_plan_digest": plan["plan_digest"],
        "expected_mode_revision": mode["revision"],
        "confirm_execute": True,
    }
    if args.submit_barrier_dir is not None:
        wait_for_submit_barrier(args.submit_barrier_dir, job_id)
    print("Approving the pinned one-package patch once", flush=True)
    submitted = call(client, "single approval", "POST", f"{PATCH}/jobs", status=202, json=payload)
    unknown = submitted.json()
    check(
        unknown["status"] == "unknown"
        and unknown["transport_unknown"] is True
        and unknown["job_id"] == job_id
        and unknown["plan_id"] == plan["plan_id"],
        "the injected disconnect did not produce an unknown original task",
    )
    waiting = export(client, endpoint, job_id, blocked)
    check(
        all(label in waiting for label in ("人工逐项批准", "任务结果未知", "待对账", PENDING))
        and RECONCILED not in waiting
        and PASSED not in waiting,
        "the disconnected summary claimed an unconfirmed outcome",
    )
    save(args.out_dir, "01-disconnected.md", waiting)
    print("Disconnected summary confirms pending reconciliation and acceptance", flush=True)

    job, queries = original_job(client, args.host_id, job_id, plan["plan_id"], args.timeout)
    proof = job["verification"]
    version = proof["exact_package_version"]
    check(
        job["evidence_origin"] == "controlled_lab"
        and job["authorization"] == "assisted"
        and job["plan_digest"] == plan["plan_digest"]
        and job["mode_revision"] == mode["revision"]
        and type(job["install_exit_code"]) is int
        and job["install_exit_code"] == 0
        and version["passed"] is True
        and version["expected"] == version["observed"] == args.expected_after
        and proof["vendor_rescan"]["passed"] is True
        and proof["vendor_rescan"]["finding_id"] == finding_id
        and proof["health"]["passed"] is True
        and proof["fresh_ssh"]["passed"] is True,
        "original receipt did not prove the exact installed version, vendor rescan, and fresh SSH",
    )
    documents = {"disconnected": waiting}
    documents.update(exercise_verified_task(client, args, original, job, blocked))
    output = {
        "approved_submissions": 1,
        "original_job_queries": queries,
        "exact_package_version_verified": True,
        "same_finding_vendor_rescan_verified": True,
        "fresh_ssh_verified": True,
    }
    if args.stop_after_reconciliation:
        output["business_recheck_started"] = False
    else:
        output["registered_http_checks_passed"] = configured
    save_acceptance(args, output, documents)


def run_existing(client, args, token, jobs):
    check(len(jobs) == 1, "cached remediation ledger must contain only the original task")
    job = jobs[0]
    check(
        job["host_id"] == args.host_id
        and job["job_id"] == args.job_id
        and job["status"] == "verified"
        and job["evidence_origin"] == "controlled_lab",
        "the selected cached job is not the original verified isolated task",
    )
    original = call(
        client, "original report detail", "GET", f"/api/reports/{args.existing_report_id}"
    ).json()
    check(
        original["id"] == args.existing_report_id
        and original["source"] == "ssh"
        and original["scenario"] == "web_502"
        and original["host_id"] == args.host_id
        and original["target"]["id"] == args.host_id
        and re.fullmatch(r"[0-9a-f]{64}", original["scope_hash"]),
        "the original report does not match the isolated task scope",
    )
    prove_mixed_registration(original, args)
    blocked = private_fields(original) | {
        token,
        args.job_id,
        args.log_marker,
        args.body_marker,
        *args.private_marker,
    }
    blocked.update(
        value
        for key in ("plan_id", "plan_digest", "policy_digest", "finding_id", "scan_id")
        if isinstance(value := job.get(key), str) and len(value) >= 8
    )
    print("Using the cached verified task without a new remediation request", flush=True)
    documents = exercise_verified_task(client, args, original, job, blocked)
    original_after = call(
        client, "original report after recovery", "GET", f"/api/reports/{args.existing_report_id}"
    ).json()
    check(original_after == original, "business rechecks changed the original investigation")
    save_acceptance(
        args,
        {
            "approved_submissions": 0,
            "original_job_queries": 0,
            "registered_http_checks_passed": 3,
            "cached_original_job_preserved": True,
        },
        documents,
    )


def exercise_verified_task(client, args, original, job, blocked):
    job_id = job["job_id"]
    endpoint = f"/api/reports/{original['id']}/handoff"
    configured = len(original["target"]["health_checks"])
    mixed = args.mixed_recheck_barrier_dir is not None
    pending = export(client, endpoint, job_id, blocked)
    check(
        all(
            label in pending
            for label in ("人工逐项批准", "补丁任务验证通过", RECONCILED, PENDING, "原调查即时检查")
        )
        and "待对账" not in pending
        and "独立只读业务复验已记录" not in pending
        and PASSED not in pending,
        "the reconciled summary did not keep business acceptance pending",
    )
    save(args.out_dir, "02-before-business-recheck.md", pending)
    print("Original task verified; business acceptance is still pending", flush=True)

    if args.stop_after_reconciliation:
        jobs = call(client, "reconciled patch ledger", "GET", PATCH).json()["jobs"]
        check(
            len(jobs) == 1
            and all(
                jobs[0].get(field) == job[field]
                for field in ("host_id", "job_id", "plan_id", "plan_digest", "revision", "status")
            ),
            "isolated controller does not retain the single reconciled task",
        )
        reports = call(client, "original report history", "GET", "/api/reports").json()
        check(
            [report["id"] for report in reports] == [original["id"]],
            "isolated controller does not retain exactly the original SSH report",
        )
        return {"before": pending}

    recheck = investigate(client, args.host_id)
    check(
        recheck["id"] != original["id"]
        and recheck["scope_hash"] == original["scope_hash"]
        and recheck["target"]["health_checks"] == original["target"]["health_checks"]
        and datetime.fromisoformat(recheck["created_at"])
        > max(datetime.fromisoformat(job[key]) for key in ("updated_at", "received_at"))
        and prove_http(recheck, args.body_marker) == configured,
        "later independent business recheck was not bound to the same scope",
    )
    if args.existing_report_id is not None:
        prove_log_marker(recheck, args.log_marker)
    if mixed:
        latest_job_record = max(
            datetime.fromisoformat(job[key]) for key in ("updated_at", "received_at")
        )
        for config in recheck["target"]["health_checks"]:
            prove_recheck(recheck, config, "passed", args.failed_body_marker, latest_job_record)
    options = call(client, "handoff choices", "GET", endpoint + "-options").json()
    check(
        any(item["id"] == job_id for item in options["jobs"])
        and any(item["id"] == recheck["id"] for item in options["rechecks"]),
        "the original task and later report were not offered as handoff choices",
    )
    blocked.update(private_fields(recheck))
    passed = export(client, endpoint, job_id, blocked, recheck=recheck["id"])
    check(
        all(
            label in passed
            for label in (
                "人工逐项批准",
                "补丁任务验证通过",
                RECONCILED,
                PASSED,
                "独立只读业务复验已记录",
                f"复验符合 {configured} / {configured} 项登记检查",
            )
        )
        and PENDING not in passed
        and FAILED not in passed
        and "待对账" not in passed,
        "the linked fresh business evidence did not pass customer acceptance",
    )
    check(
        export(client, endpoint, job_id, blocked) == pending,
        "an unselected report changed the summary",
    )
    save(args.out_dir, "03-after-business-recheck.md", passed)
    documents = {"before": pending, "after": passed}
    if mixed or args.negative_recheck_barrier_dir is not None:
        documents.update(exercise_rechecks(client, args, endpoint, job_id, recheck, blocked))
        check(
            export(client, endpoint, job_id, blocked) == pending
            and export(client, endpoint, job_id, blocked, recheck=recheck["id"]) == passed,
            "negative rechecks changed the unlinked summary or the separate successful recheck",
        )
    jobs = call(client, "post-run patch ledger", "GET", PATCH).json()["jobs"]
    if args.existing_report_id is not None:
        check(jobs == [job], "business rechecks changed the cached original job ledger")
    else:
        check(
            len(jobs) == 1 and jobs[0]["job_id"] == job_id and jobs[0]["status"] == "verified",
            "isolated controller contains an unexpected extra patch job",
        )
    return documents


def save_acceptance(args, output, documents):
    output.update(
        pending_summary_stable_without_explicit_recheck=True,
        private_markers_absent=True,
        customer_summary_sha256={
            label: hashlib.sha256(document.encode()).hexdigest()
            for label, document in documents.items()
        },
    )
    if args.negative_recheck_barrier_dir is not None:
        output["complete_http_mismatch_marked_failed"] = True
        output["curl_timeout_without_metadata_kept_pending"] = True
    if args.mixed_recheck_barrier_dir is not None:
        output["mixed_failure_overrides_timeout"] = True
        output["mixed_success_and_timeout_kept_pending"] = True
        output["restored_three_checks_passed"] = True
        output["failed_and_pending_reports_preserved"] = True
    save(args.out_dir, "acceptance.json", json.dumps(output, indent=2) + "\n")
    if args.stop_after_reconciliation:
        print("Native task reconciled and privacy-checked for browser handoff", flush=True)
    else:
        print("Business recheck and all customer artifact privacy assertions passed", flush=True)


def save(directory, filename, document):
    with (directory / filename).open("x", encoding="utf-8", newline="\n") as file:
        file.write(document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in (
        "url",
        "host-id",
        "package",
        "expected-before",
        "expected-after",
        "body-marker",
        "log-marker",
    ):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--advisory")
    parser.add_argument("--job-id")
    parser.add_argument(
        "--existing-report-id",
        help="Use a private lab fixture or historical anchor with repair disabled; no native proof",
    )
    parser.add_argument("--submit-barrier-dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--negative-recheck-barrier-dir", type=Path)
    mode.add_argument("--mixed-recheck-barrier-dir", type=Path)
    mode.add_argument(
        "--stop-after-reconciliation",
        action="store_true",
        help="Verify the fresh native task and leave its original SSH report for browser rechecks",
    )
    parser.add_argument("--failed-body-marker")
    parser.add_argument("--private-marker", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()
    try:
        target = urlsplit(args.url)
        check(
            target.scheme == "http"
            and target.hostname == "127.0.0.1"
            and target.port is not None
            and target.username is None
            and target.password is None
            and target.path in {"", "/"}
            and not target.query
            and not target.fragment,
            "controller URL must be a dedicated IPv4 loopback listener",
        )
        check(
            args.job_id is None or re.fullmatch(r"[0-9a-f]{32}", args.job_id),
            "original job ID must have 32 lowercase hex characters",
        )
        check(
            args.existing_report_id is None
            or (
                re.fullmatch(r"[A-Za-z0-9_-]{1,80}", args.existing_report_id)
                and args.job_id is not None
                and args.mixed_recheck_barrier_dir is not None
                and args.submit_barrier_dir is None
            ),
            "cached original task reuse requires its job ID, report ID and mixed recheck barrier",
        )
        check(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", args.host_id)
            and all(
                len(value) >= 8
                for value in (args.body_marker, args.log_marker, *args.private_marker)
            )
            and args.expected_before != args.expected_after
            and args.timeout > 0,
            "target, version transition, timeout or marker arguments are invalid",
        )
        directory = args.mixed_recheck_barrier_dir or args.negative_recheck_barrier_dir
        failed_marker = args.failed_body_marker
        check(
            (directory is None and failed_marker is None)
            or (
                directory is not None
                and directory.is_dir()
                and not any(directory.iterdir())
                and failed_marker is not None
                and len(failed_marker) >= 8
                and args.body_marker not in failed_marker
            ),
            "recheck fixtures require a fresh barrier directory and a distinct wrong body marker",
        )
        token = args.token_file.read_text(encoding="utf-8").strip()
        check(
            len(token) >= 16 and not any(character.isspace() for character in token),
            "invalid token file",
        )
        args.out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        check(not any(args.out_dir.iterdir()), "output directory must be empty")
        with httpx.Client(
            base_url=args.url,
            trust_env=False,
            timeout=95,
            headers={"Authorization": "Bearer " + token},
        ) as client:
            run(client, args, token)
    except RuntimeError as error:
        parser.exit(1, f"Handoff acceptance failed: {error}\n")
    except (httpx.HTTPError, ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"Handoff acceptance failed: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
