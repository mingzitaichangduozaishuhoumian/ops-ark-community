"""Drive first-use onboarding against an actual isolated OpsArk controller."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

FORM_FIELDS = (
    "host_id",
    "name",
    "address",
    "port",
    "username",
    "site_domain",
    "container_name",
    "expected_upstream_port",
    "host_key",
    "expected_fingerprint",
)
MATERIAL_FIELDS = {
    "host_id",
    "address",
    "port",
    "fingerprint",
    "inventory",
    "known_hosts",
    "key_file",
    "known_hosts_file",
    "known_hosts_digests",
}


class EvidenceError(RuntimeError):
    """Carry a fixed failure category without browser or fixture values."""


def require(condition: object, stage: str = "evidence") -> None:
    if not condition:
        raise EvidenceError(stage)


def read_private(path: Path) -> dict:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 32_768)
    if sys.platform != "win32":
        require(not info.st_mode & 0o077)
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict))
    return value


def write_private(path: Path, value: dict) -> None:
    require(path.is_absolute() and not path.exists() and not path.is_symlink())
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def report_digest(report: dict) -> str:
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def local_files(args) -> tuple[Path, dict | None, dict | None]:
    record_path = args.record or args.materials.with_name(args.materials.name + ".readback.json")
    require(
        all(path.is_absolute() for path in (args.materials, record_path, args.proof)), "local_files"
    )
    outputs = [args.proof]
    if args.phase == "prepare":
        outputs.append(args.materials)
    elif args.phase == "verify":
        outputs.append(record_path)
    require(
        len({path.resolve() for path in outputs}) == len(outputs)
        and all(not path.exists() and not path.is_symlink() for path in outputs),
        "local_files",
    )
    materials = read_private(args.materials) if args.phase != "prepare" else None
    record = read_private(record_path) if args.phase == "readback" else None
    return record_path, materials, record


def descriptor(path: Path) -> dict:
    value = read_private(path)
    url = urlsplit(value.get("url", ""))
    require(
        url.scheme == "http"
        and url.hostname in {"127.0.0.1", "localhost"}
        and url.port is not None
        and not url.username
        and not url.password
        and not url.query
        and not url.fragment
        and url.path in {"", "/"}
    )
    require(isinstance(value.get("token"), str) and 32 <= len(value["token"]) <= 1024)
    target = value.get("target")
    if not isinstance(target, dict) or set(target) != set(FORM_FIELDS):
        raise RuntimeError("Invalid private onboarding fixture form")
    require(
        target["username"] == "opsark-readonly"
        and target["port"] == 22
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", target["host_id"])
        and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", target["expected_fingerprint"])
    )
    ipaddress.ip_address(target["address"])
    canaries = value.get("canaries", [])
    require(isinstance(canaries, list) and all(isinstance(item, str) and item for item in canaries))
    return value


def matches(response, path: str, method: str = "POST") -> bool:
    return urlsplit(response.url).path == path and response.request.method == method


def report_ready(page, report_id: str) -> None:
    expect(page.locator("#report-id")).to_have_text(report_id)
    expect(page.locator(f'button[data-report-id="{report_id}"]')).to_have_attribute(
        "aria-pressed", "true"
    )
    expect(page.locator("#app-message")).to_be_hidden()
    expect(page.locator("#app-error")).to_be_hidden()
    expect(page.locator("#export-handoff")).to_be_enabled()


def login(page, data: dict) -> None:
    page.goto(data["url"], wait_until="networkidle")
    page.locator("#token-input").fill(data["token"])
    page.locator("#login-button").click()
    expect(page.locator("#app-shell")).to_be_visible()
    expect(page.locator("#app-message")).to_be_hidden()
    expect(page.locator("#app-error")).to_be_hidden()
    history = page.locator("#report-list button[data-report-id]")
    if history.count():
        selected = history.first.get_attribute("data-report-id")
        require(isinstance(selected, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", selected))
        report_ready(page, selected)


def prepare(page, data: dict, materials_path: Path) -> dict[str, bool]:
    target = data["target"]
    page.locator('button[data-view="hosts"]').click()
    expect(page.locator(".host-card")).to_have_count(0)
    expect(page.locator("#host-onboarding")).to_be_visible()
    page.locator("#host-onboarding > summary").click()
    for name in FORM_FIELDS:
        page.locator(f'#host-onboarding-form [name="{name}"]').fill(str(target[name]))
    digest = target["expected_fingerprint"]
    wrong = digest[:7] + ("B" if digest[7] == "A" else "A") + digest[8:]
    page.locator('#host-onboarding-form [name="expected_fingerprint"]').fill(wrong)
    page.locator("#host-onboarding-confirm").check()
    with page.expect_response(
        lambda reply: matches(reply, "/api/host-onboarding/prepare")
    ) as failed:
        page.locator("#host-onboarding-prepare").click()
    require(failed.value.status == 422)
    expect(page.locator("#host-onboarding-error")).to_be_visible()
    expect(page.locator("#host-onboarding-error")).to_contain_text("指纹")
    expect(page.locator("#host-onboarding-result")).to_be_hidden()

    page.locator('#host-onboarding-form [name="expected_fingerprint"]').fill(digest)
    page.locator("#host-onboarding-confirm").check()
    with page.expect_response(
        lambda reply: matches(reply, "/api/host-onboarding/prepare")
    ) as accepted:
        page.locator("#host-onboarding-prepare").click()
    require(accepted.value.status == 200)
    materials = accepted.value.json()
    require(
        isinstance(materials, dict)
        and set(materials) == MATERIAL_FIELDS
        and materials["host_id"] == target["host_id"]
        and materials["address"] == target["address"]
        and materials["port"] == target["port"]
        and materials["fingerprint"] == digest
    )
    expect(page.locator("#host-onboarding-preflight")).to_be_hidden()
    expect(page.locator("#host-onboarding-result")).to_be_visible()
    require(
        page.locator("#host-onboarding-inventory").input_value() == materials["inventory"]
        and page.locator("#host-onboarding-known-hosts").input_value() == materials["known_hosts"]
        and page.locator("#host-onboarding-key-file").inner_text() == materials["key_file"]
        and page.locator("#host-onboarding-known-hosts-file").inner_text()
        == materials["known_hosts_file"]
    )
    require(
        hashlib.sha256(materials["known_hosts"].encode("ascii")).hexdigest()
        == materials["known_hosts_digests"]["lf"]
    )
    write_private(materials_path, materials)
    return {
        "wrong_fingerprint_refused": True,
        "correct_fingerprint_verified": True,
        "exact_ui_materials_saved_privately": True,
    }


def verify_report(report: dict, target: dict) -> None:
    require(
        report["host_id"] == target["host_id"]
        and report["source"] == "ssh"
        and report["scenario"] == "web_502"
        and report["action"]["executable"] is False
        and report["compatibility"]["status"] == "compatible"
        and report["compatibility"]["os_id"] == "ubuntu"
        and bool(report["missing"])
    )
    errors = [item for item in report["evidence"] if item["check_id"] == "nginx_errors"]
    require(
        len(errors) == 1
        and errors[0]["source"] == "ssh"
        and errors[0]["status"] == "ok"
        and errors[0]["exit_code"] == 0
        and not errors[0]["truncated"]
        and "Connection refused" in errors[0]["output"]
        and f"127.0.0.1:{target['expected_upstream_port']}" in errors[0]["output"]
    )
    require(
        any(
            "上游连接被拒绝" in item["text"]
            and str(target["expected_upstream_port"]) in item["text"]
            and item["evidence_ids"] == ["E-NGINX-ERRORS"]
            for item in report["facts"]
        )
    )
    checks = {item["check_id"]: item for item in report["evidence"]}
    require(
        checks["container_state"]["status"] == "unavailable"
        and checks["nginx_status"]["status"] in {"unavailable", "error", "permission_denied"}
    )
    require(
        any(item["status"] == "not_run" for item in report["verification"])
        and report["comparison"]["restore_capable"] is False
    )


def download_summary(page, report: dict, data: dict, materials: dict) -> bytes:
    path = f"/api/reports/{report['id']}/handoff"
    page.locator("#export-handoff").click()
    expect(page.locator("#handoff-dialog")).to_be_visible()
    expect(page.locator("#handoff-download")).to_be_enabled()
    with (
        page.expect_response(lambda reply: matches(reply, path, "GET")) as response,
        page.expect_download() as saved,
    ):
        page.locator("#handoff-download").click()
    require(response.value.status == 200 and saved.value.suggested_filename == "opsark-handoff.md")
    content = Path(saved.value.path()).read_bytes()
    require(0 < len(content) <= 65_536)
    text = content.decode("utf-8")
    require("客户交接摘要" in text and "待验收" in text and "-----BEGIN" not in text)
    target = data["target"]
    banned = [
        data["token"],
        target["host_id"],
        target["address"],
        target["site_domain"],
        target["host_key"].split()[1],
        materials["key_file"],
        materials["known_hosts_file"],
        *data.get("canaries", []),
    ]
    require(all(item not in text for item in banned))
    return content


def verify(page, data: dict, materials: dict, record_path: Path) -> dict[str, bool]:
    target = data["target"]
    page.locator('button[data-view="hosts"]').click()
    card = page.locator(f'.host-card[data-host-id="{target["host_id"]}"]')
    expect(card).to_be_visible()
    path = f"/api/hosts/{target['host_id']}/preflight"
    with page.expect_response(lambda reply: matches(reply, path)) as checked:
        card.get_by_role("button", name="运行接入预检", exact=True).click()
    require(checked.value.status == 200)
    preflight = checked.value.json()
    checks = {item["id"]: item["status"] for item in preflight["checks"]}
    require(
        preflight["connection"] == "ok"
        and preflight["platform"] == "compatible"
        and preflight["os_family"] == "ubuntu"
        and preflight["status"] == "needs_attention"
        and "docker" in preflight["missing_tools"]
        and checks["container_state"] == "unavailable"
        and checks["nginx_status"] in {"unavailable", "error", "permission_denied"}
    )
    expect(card.locator("[data-host-preflight-result]")).to_have_attribute(
        "data-status", "needs_attention"
    )
    card.get_by_role("button", name="对此主机发起只读调查 →", exact=True).click()
    expect(page.locator("#source-select")).to_have_value("ssh")
    expect(page.locator("#host-select")).to_have_value(target["host_id"])
    page.locator("#scenario-select").select_option("web_502")
    with page.expect_response(lambda reply: matches(reply, "/api/investigations")) as result:
        page.locator("#run-investigation").click()
    require(result.value.status == 200)
    report = result.value.json()
    verify_report(report, target)
    expect(page.locator("#report-id")).to_have_text(report["id"])
    expect(page.locator("#run-investigation")).to_be_enabled()
    expect(page.locator("#report-source")).to_contain_text("SSH")
    page.locator("#tab-evidence").click()
    error = page.locator('details[data-evidence-id="E-NGINX-ERRORS"]')
    error.locator("summary").click()
    expect(error).to_contain_text("Connection refused")
    content = download_summary(page, report, data, materials)
    write_private(
        record_path,
        {
            "host_id": report["host_id"],
            "report_id": report["id"],
            "scope_hash": report["scope_hash"],
            "report_sha256": report_digest(report),
            "summary_sha256": hashlib.sha256(content).hexdigest(),
        },
    )
    return {
        "native_ssh_preflight_verified": True,
        "missing_components_shown_honestly": True,
        "real_502_investigation_verified": True,
        "readonly_report_and_gaps_retained": True,
        "customer_summary_private_fields_excluded": True,
    }


def readback(page, data: dict, materials: dict, record: dict) -> dict[str, bool]:
    require(record["host_id"] == data["target"]["host_id"])
    page.locator('button[data-view="workspace"]').click()
    report_id = record["report_id"]
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", report_id))
    path = f"/api/reports/{report_id}"
    with page.expect_response(lambda reply: matches(reply, path, "GET")) as result:
        page.locator(f'button[data-report-id="{report_id}"]').click()
    require(result.value.status == 200)
    report = result.value.json()
    verify_report(report, data["target"])
    require(
        report["scope_hash"] == record["scope_hash"]
        and report_digest(report) == record["report_sha256"]
    )
    report_ready(page, report_id)
    content = download_summary(page, report, data, materials)
    require(hashlib.sha256(content).hexdigest() == record["summary_sha256"])
    return {"report_survived_restart": True, "customer_summary_bytes_identical": True}


def run(args) -> dict[str, bool]:
    record_path, materials, record = local_files(args)
    data = descriptor(args.descriptor)
    origin = urlsplit(data["url"])
    failures, mutations = [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                accept_downloads=True,
                service_workers="block",
                viewport={"width": 1440, "height": 1000},
            )
            context.set_default_timeout(args.timeout * 1000)
            page = context.new_page()
            page.on("pageerror", lambda _error: failures.append(True))

            def observed(request):
                url = urlsplit(request.url)
                local_blob = request.url.startswith(f"blob:{origin.scheme}://{origin.netloc}/")
                if not local_blob and (url.scheme, url.netloc) != (origin.scheme, origin.netloc):
                    failures.append(True)
                if request.method not in {"GET", "HEAD"}:
                    mutations.append((request.method, url.path))

            page.on("request", observed)
            login(page, data)
            if args.phase == "prepare":
                proof = prepare(page, data, args.materials)
                require(mutations == [("POST", "/api/host-onboarding/prepare")] * 2)
            elif args.phase == "verify":
                if materials is None:
                    raise EvidenceError("local_files")
                proof = verify(page, data, materials, record_path)
                require(
                    mutations
                    == [
                        ("POST", f"/api/hosts/{data['target']['host_id']}/preflight"),
                        ("POST", "/api/investigations"),
                    ]
                )
            else:
                if materials is None or record is None:
                    raise EvidenceError("local_files")
                proof = readback(page, data, materials, record)
                require(not mutations)
            require(not failures)
            context.close()
        finally:
            browser.close()
    return proof | {"real_backend_without_browser_mocks": True, "unexpected_writes_absent": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--phase", choices=("prepare", "verify", "readback"), required=True)
    parser.add_argument("--materials", type=Path, required=True)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    try:
        proof = run(args)
        write_private(args.proof, proof)
        print(json.dumps(proof, sort_keys=True))
    except Exception as error:
        stage = str(error) if isinstance(error, EvidenceError) else args.phase
        print(
            f"The isolated onboarding browser check failed ({stage}).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
