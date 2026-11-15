"""Offline, real-process Controller history recovery using an existing owned lab.

The caller supplies original deployment path references. Formal loaders may read
the lab's synthetic credentials opaquely; neither this driver nor its evidence
exports credential bytes. There is no live Root reconnect, host/container restart,
action replay, model call or new business collection in this acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from opsark.config import Settings  # noqa: E402 -- exact worktree source under -I.

DATABASES = (
    "reports.sqlite3",
    "baselines.sqlite3",
    "security.sqlite3",
    "web-security.sqlite3",
    "security-ai.sqlite3",
    "automation.sqlite3",
    "patches.sqlite3",
    "vulnerability-ai.sqlite3",
    "automatic.sqlite3",
    "vulnerability-watch.sqlite3",
)
PATH_FIELDS = {
    "data_dir",
    "inventory_path",
    "automation_policy_path",
    "patch_inventory_path",
    "defense_inventory_path",
    "defense_policy_path",
}


class RestartAcceptanceError(RuntimeError):
    """Only a bounded public phase code can escape a failed acceptance."""


def require(condition, code):
    if not condition:
        raise RestartAcceptanceError(code)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json(path: Path, value):
    # Existence is the subprocess handshake: never expose an empty/partial JSON
    # file to its waiting parent. A hard link publishes without replacing an
    # existing destination on either NTFS or the Unix filesystems used here.
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12) + ".pending")
    try:
        with temporary.open("x", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _feed(hasher, value):
    """Length-delimited SQLite scalar encoding; no original content is returned."""
    if value is None:
        raw = b"n"
    elif isinstance(value, bytes):
        raw = b"b" + value
    elif isinstance(value, str):
        raw = b"s" + value.encode("utf-8")
    elif isinstance(value, int):
        raw = b"i" + str(value).encode("ascii")
    elif isinstance(value, float):
        raw = b"f" + value.hex().encode("ascii")
    else:
        raise RestartAcceptanceError("unsupported_sqlite_scalar")
    hasher.update(len(raw).to_bytes(8, "big"))
    hasher.update(raw)


def _quoted(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def database_images(directory: Path) -> dict:
    """Read all ten logical images, preserving hidden rowids and sqlite_sequence."""
    images = {}
    for name in DATABASES:
        path = directory / name
        require(
            path.is_file() and not path.is_symlink() and not path.is_junction(), "store_missing"
        )
        hasher, count = hashlib.sha256(b"opsark-logical-database/v1\n"), 0
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            catalog = connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
            for row in catalog:
                for value in row:
                    _feed(hasher, value)
            for kind, table, _, sql in catalog:
                if kind != "table":
                    continue
                _feed(hasher, table)
                columns = connection.execute("PRAGMA table_info(" + _quoted(table) + ")").fetchall()
                if "WITHOUT ROWID" in (sql or "").upper():
                    ordering = ",".join(_quoted(row[1]) for row in columns)
                    query = "SELECT * FROM " + _quoted(table) + " ORDER BY " + ordering  # noqa: S608 -- catalog identifiers are SQL-quoted.
                else:
                    query = "SELECT _rowid_,* FROM " + _quoted(table) + " ORDER BY _rowid_"  # noqa: S608 -- catalog identifiers are SQL-quoted.
                for row in connection.execute(query):
                    count += 1
                    for value in row:
                        _feed(hasher, value)
        images[name] = {"sha256": hasher.hexdigest(), "rows": count}
    return images


@dataclass(frozen=True)
class StoredRun:
    run_ref: str
    historical_verdict: str
    status: str = "completed"


@dataclass(frozen=True)
class OriginalHistory:
    host_id: str
    request_id: str
    runs: tuple[StoredRun, ...]


def sealed_runs(directory: Path, history: OriginalHistory) -> dict:
    path = directory / "security.sqlite3"
    images = {}
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        for run in history.runs:
            row = connection.execute(
                "SELECT r.sequence,r.declaration_sha256,r.typed_declaration,r.claim_sha256,"
                "r.typed_claim,s.result_sha256,s.typed_result,r.interruption_sha256,"
                "r.typed_interruption FROM defense_recheck_runs_v2 AS r "
                "LEFT JOIN defense_recheck_results_v2 AS s ON s.run_ref=r.run_ref "
                "WHERE r.run_ref=? AND r.host_id=? AND r.rid=?",
                (run.run_ref, history.host_id, history.request_id),
            ).fetchone()
            require(row is not None, "original_run_missing")
            hasher = hashlib.sha256(b"opsark-sealed-recheck-row/v1\n")
            for value in row:
                _feed(hasher, value)
            images[_sha(run.run_ref.encode("ascii"))] = hasher.hexdigest()
    return images


def _settings_document(settings: Settings):
    require(
        not any((settings.ai_base_url, settings.ai_key, settings.ai_key_file, settings.ai_model))
        and not settings.defense_worker_enabled
        and not settings.defense_session_enabled
        and not settings.defense_task_watch_enabled
        and not settings.observation_enabled
        and not settings.vulnerability_scan_enabled
        and settings.vulnerability_webhook_url is None
        and settings.vulnerability_webhook_key_file is None,
        "offline_settings_required",
    )
    document = asdict(settings)
    for field in PATH_FIELDS:
        if document[field] is not None:
            document[field] = str(document[field])
    return document


def _decode_settings(document):
    """Decode deployment references and explicit tuple fields from private stdin."""
    document = dict(document)
    for name in PATH_FIELDS:
        if document.get(name) is not None:
            document[name] = Path(document[name])
    for name in (
        "observation_host_ids",
        "vulnerability_scan_host_ids",
        "defense_task_watch_host_ids",
    ):
        if name in document:
            require(type(document[name]) in (list, tuple), "invalid_tuple_settings")
            document[name] = tuple(document[name])
    settings = Settings(**document)
    _settings_document(settings)
    return settings


def _read(base, token, path, method="GET"):
    parsed = urlsplit(base)
    require(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
        and not parsed.username
        and not parsed.password
        and not parsed.path
        and not parsed.query
        and not parsed.fragment,
        "non_loopback_observer",
    )
    opener = build_opener(ProxyHandler({}))
    request = Request(base + path, headers={"Authorization": "Bearer " + token}, method=method)  # noqa: S310 -- exact validated HTTP loopback origin.
    try:
        with opener.open(request, timeout=10) as response:
            return (
                response.status,
                response.read(),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except HTTPError as error:
        return (
            error.code,
            error.read(),
            {key.lower(): value for key, value in error.headers.items()},
        )


def _observe(base, settings, history, output, index, *, browser, verify_write_barrier):
    prefix = "/api/hosts/" + quote(history.host_id, safe="") + "/ssh-defense/transactions/"
    prefix += quote(history.request_id, safe="")
    status, raw, _ = _read(base, settings.token, "/api/ssh-defense/history-targets")
    require(
        status == 200 and {"host_id": history.host_id} in json.loads(raw)["history_targets"],
        "history_missing",
    )
    status, raw, _ = _read(base, settings.token, prefix)
    require(status == 200 and json.loads(raw)["request_id"] == history.request_id, "task_missing")
    status, raw, _ = _read(base, settings.token, prefix + "/rechecks")
    require(status == 200, "run_history_missing")
    listing = json.loads(raw)
    observed, expected_exports = [], {}
    for ordinal, run in enumerate(history.runs, 1):
        status, raw, _ = _read(base, settings.token, prefix + "/rechecks/" + run.run_ref)
        row = json.loads(raw)
        require(
            status == 200
            and row["run_ref"] == run.run_ref
            and row["request_id"] == history.request_id
            and row["status"] == run.status
            and row["historical_verdict"] == run.historical_verdict,
            "original_run_changed",
        )
        status, raw, headers = _read(
            base, settings.token, prefix + "/handoff?run_ref=" + run.run_ref
        )
        require(
            status == 200 and "attachment" in headers.get("content-disposition", ""),
            "export_missing",
        )
        text = raw.decode("utf-8")
        require(text.startswith("# OpsArk 防护任务交接摘要"), "export_shape_changed")
        require(
            not any(
                value in text
                for value in (settings.token, history.host_id, history.request_id, run.run_ref)
            )
            and "-----BEGIN" not in text
            and "key_file" not in text
            and "source_ref" not in text,
            "export_private_content",
        )
        destination = output / f"process-{index}-run-{ordinal}.md"
        with destination.open("xb") as stream:
            stream.write(raw)
        expected_exports[run.run_ref] = _sha(raw)
        observed.append(
            {
                "run_ref_sha256": _sha(run.run_ref.encode()),
                "status": row["status"],
                "historical_verdict": row["historical_verdict"],
                "current_verdict": row["current_verdict"],
                "summary_sha256": _sha(raw),
            }
        )
    claimed = [run.run_ref for run in history.runs if run.status == "claimed"]
    if claimed:
        require(
            len(claimed) == 1
            and listing["active_run_ref"] == claimed[0]
            and not listing["can_run"],
            "claim_replayed",
        )
    if verify_write_barrier:
        require(
            _read(base, settings.token, prefix + "/rechecks", "POST")[0] == 405,
            "write_barrier_failed",
        )
    if browser:
        _browser_observe(base, settings.token, history, expected_exports)
    return observed


def _browser_observe(base, token, history, expected_exports):
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        requests, errors = [], []
        page = context.new_page()
        page.on("request", lambda request: requests.append((request.method, request.url)))
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        try:
            page.goto(base)
            page.locator("#token-input").fill(token)
            page.locator("#login-form").evaluate("form => form.requestSubmit()")
            expect(page.locator("#app-shell")).to_be_visible()
            page.locator('button[data-view="security"]').click()
            page.locator('[data-defense="history"] .ssh-defense-row').filter(
                has_text=history.request_id
            ).click()
            select = page.locator("[data-defense-recheck=selection]")
            for run in history.runs:
                expect(select.locator('option[value="' + run.run_ref + '"]')).to_have_count(1)
            for run in history.runs:
                if select.input_value() != run.run_ref:
                    with page.expect_response(
                        lambda response, ref=run.run_ref: (
                            response.request.method == "GET"
                            and response.url.endswith("/rechecks/" + ref)
                        )
                    ) as selected:
                        select.select_option(run.run_ref)
                    require(selected.value.status == 200, "browser_selection_unavailable")
                expect(select).to_have_value(run.run_ref)
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="导出所选复验的安全摘要", exact=True).click()
                require(
                    downloaded.value.suggested_filename == "opsark-defense-handoff.md",
                    "browser_export_changed",
                )
                require(
                    _sha(Path(downloaded.value.path()).read_bytes())
                    == expected_exports[run.run_ref],
                    "browser_export_wrong_run",
                )
            require(not errors, "browser_error")
            require(
                all(
                    method in {"GET", "HEAD"} and url.startswith(base + "/")
                    for method, url in requests
                ),
                "browser_unplanned_request",
            )
        finally:
            context.close()
            browser.close()


def run_offline_restart(
    settings: Settings,
    history: OriginalHistory,
    *,
    output: Path,
    browser: bool = True,
    verify_write_barrier: bool = False,
) -> dict:
    """Two independent Python PIDs; original stores are opened, never copied/adopted."""
    require(
        settings.data_dir.is_absolute() and settings.data_dir.is_dir(), "data_directory_missing"
    )
    require(
        not settings.data_dir.is_symlink() and not settings.data_dir.is_junction(),
        "linked_data_directory",
    )
    require(
        output.is_absolute() and not output.exists() and output.parent.is_dir(), "output_not_fresh"
    )
    configuration = _settings_document(settings)
    before = database_images(settings.data_dir)
    sealed_before = sealed_runs(settings.data_dir, history)
    output.mkdir(mode=0o700)
    records = []
    for index in (1, 2):
        ready, stop, audit = (
            output / f"process-{index}-{name}.json" for name in ("ready", "stop", "audit")
        )
        payload = {
            "settings": configuration,
            "ready": str(ready),
            "stop": str(stop),
            "audit": str(audit),
        }
        environment = {
            name: value for name, value in os.environ.items() if not name.startswith("OPSARK_")
        }
        process = subprocess.Popen(  # noqa: S603 -- fixed Python entry, private owned paths via stdin.
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        stream = process.stdin
        if stream is None:
            raise RestartAcceptanceError("child_input_missing")
        stream.write(json.dumps(payload).encode("utf-8"))
        stream.close()
        try:
            deadline = time.monotonic() + 20
            while not ready.exists():
                require(process.poll() is None, "child_start_failed")
                require(time.monotonic() < deadline, "child_start_timeout")
                time.sleep(0.03)
            state = json.loads(ready.read_text(encoding="ascii"))
            require(
                state["pid"] == process.pid
                or (os.name == "nt" and state["parent_pid"] == process.pid),
                "child_identity_changed",
            )
            observed = _observe(
                state["base"],
                settings,
                history,
                output,
                index,
                browser=browser,
                verify_write_barrier=verify_write_barrier,
            )
        finally:
            _json(stop, {"stop": True})
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise RestartAcceptanceError("child_stop_timeout") from None
        require(process.returncode == 0 and audit.is_file(), "child_failed")
        final = json.loads(audit.read_text(encoding="ascii"))
        require(
            final["ssh_attempts"] == 0
            and final["model_attempts"] == 0
            and final["blocked_writes"] == int(verify_write_barrier)
            and final["production_root_invoker"]
            and final["production_business_collector"],
            "offline_boundary_failed",
        )
        require(database_images(settings.data_dir) == before, "database_image_changed")
        require(sealed_runs(settings.data_dir, history) == sealed_before, "sealed_run_changed")
        records.append(
            {**final, "runs": observed, "stores_unchanged": True, "sealed_runs_unchanged": True}
        )
    require(records[0]["pid"] != records[1]["pid"], "process_identity_reused")
    proof = {
        "schema": "opsark-offline-controller-process-restart/v1",
        "completed": True,
        "controller_process_restart_verified": True,
        "live_root_reconnect_verified": False,
        "host_or_container_restart_verified": False,
        "business_recollection": False,
        "ai_dispatches": 0,
        "resident_modified": False,
        "browser_verified": browser,
        "database_images_before_between_after": before,
        "sealed_runs": sealed_before,
        "processes": records,
    }
    _json(output / "proof.json", proof)
    return proof


def _child():
    """Fixed private child entry: no external response, credentials or logs are printed."""
    payload = json.loads(sys.stdin.buffer.read(32769))
    ready, stop, audit = (Path(payload[name]) for name in ("ready", "stop", "audit"))
    counts: dict[str, Any] = {
        "pid": os.getpid(),
        "ssh_attempts": 0,
        "model_attempts": 0,
        "blocked_writes": 0,
        "read_requests": 0,
    }
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    settings = _decode_settings(payload["settings"])
    os.environ["OPSARK_DATA_DIR"] = str(ready.parent / ("bootstrap-" + str(os.getpid())))
    os.environ["OPSARK_TOKEN"] = settings.token
    import httpx
    import paramiko
    import uvicorn
    from starlette.responses import Response

    def no_ssh(*_args, **_kwargs):
        counts["ssh_attempts"] += 1
        raise RestartAcceptanceError("ssh_forbidden")

    async def no_model(*_args, **_kwargs):
        counts["model_attempts"] += 1
        raise RestartAcceptanceError("model_forbidden")

    paramiko.SSHClient.connect = no_ssh
    httpx.AsyncClient.send = no_model
    try:
        from opsark.business_readiness import run_business_readiness
        from opsark.defense_client import invoke
        from opsark.main import create_app

        app = create_app(settings)
        counts["production_root_invoker"] = app.state.defense_service.invoker is invoke
        counts["production_business_collector"] = (
            app.state.defense_recheck_service.collector is run_business_readiness
        )

        @app.middleware("http")
        async def readonly(request, call_next):
            if request.method not in {"GET", "HEAD"}:
                counts["blocked_writes"] += 1
                return Response(status_code=405)
            counts["read_requests"] += 1
            return await call_next(request)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                loop="asyncio",
                http="h11",
                ws="none",
                access_log=False,
                log_level="critical",
                timeout_graceful_shutdown=2,
            )
        )

        def supervise():
            while not server.started:
                if stop.exists():
                    server.should_exit = True
                    return
                time.sleep(0.02)
            _json(
                ready,
                {
                    "pid": os.getpid(),
                    "parent_pid": os.getppid(),
                    "base": f"http://127.0.0.1:{port}",
                },
            )
            while not stop.exists():
                time.sleep(0.03)
            server.should_exit = True

        supervisor = threading.Thread(target=supervise, daemon=True)
        supervisor.start()
        try:
            server.run(sockets=[listener])
        finally:
            listener.close()
        supervisor.join(timeout=1)
        require(not supervisor.is_alive(), "supervisor_not_stopped")
        counts["stopped"] = True
        _json(audit, counts)
        return 0
    except Exception as error:
        counts["failure_type"] = type(error).__name__
        _json(audit, counts)
        return 1


if __name__ == "__main__":
    require(sys.argv[1:] == ["--child"], "invalid_child_entry")
    raise SystemExit(_child())
