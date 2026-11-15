"""A fixed owned child that exits before recording an unconfirmed apply result.

The client only exposes a normalized post-dispatch unknown result. The native
operator must independently bind its exact socket-fault marker to this request;
this fixture never invents an EOF, Root acceptance or business receipt.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import defense_live_process as live  # noqa: E402
from defense_recheck_process_restart import require  # noqa: E402

from opsark.defense_client import UnknownDefenseResult  # noqa: E402

EXIT_CODE = 91
BOUNDARY = "apply_result_unknown_before_unavailable_commit"


def uncommitted_apply(directory: Path, rid: str) -> dict:
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        row = db.execute(
            "SELECT r.dispatch_phase,r.reply_sha256,t.phase,t.query_required "
            "FROM defense_requests r JOIN defense_transactions t ON t.rid=r.rid "
            "WHERE r.rid=? AND r.op='apply'",
            (rid,),
        ).fetchone()
        require(row is not None, "apply_intent_missing")
        count = db.execute(
            "SELECT count(*) FROM defense_observations WHERE rid=? AND op='apply'", (rid,)
        ).fetchone()[0]
    return {
        "dispatch_phase": row[0],
        "reply_committed": row[1] is not None,
        "transaction_phase": row[2],
        "query_required": bool(row[3]),
        "apply_observations": count,
    }


def immutable_submission(directory: Path, rid: str) -> str:
    """Hash original identity/bytes/accounting, excluding legitimate query state."""
    queries = (
        "SELECT rowid,rid,kind,host_id,defense_scope,context_json,context_sha256,owner,"
        "deadline_at,cursor_rid,created_at,manifest_sha256,manifest_json,action_id "
        "FROM defense_transactions WHERE rid=?",
        "SELECT rowid,* FROM defense_requests "
        "WHERE rid=? AND op IN ('prepare','apply') ORDER BY op",
        "SELECT rowid,* FROM defense_authorizations "
        "WHERE rid=? AND purpose='apply' ORDER BY purpose",
        "SELECT rowid,* FROM defense_usage WHERE rid=? ORDER BY intent_key",
    )
    hasher = hashlib.sha256(b"opsark-abrupt-original-submission/v1\n")
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        for query in queries:
            hasher.update(repr(db.execute(query, (rid,)).fetchall()).encode("utf-8"))
    return hasher.hexdigest()


def _durable_json(path, value):
    with path.open("x", encoding="ascii") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def _application(settings):
    from opsark.main import create_app

    return create_app(settings)


def _crash_application(settings, payload):
    import httpx

    from opsark.business_readiness import run_business_readiness
    from opsark.defense_client import invoke

    app = _application(settings)
    controller, rechecks = app.state.defense_service, app.state.defense_recheck_service
    counts: dict[str, Any] = {
        "pid": os.getpid(),
        "model_attempts": 0,
        "read_requests": 0,
        "write_requests": {},
        "production_root_invoker": controller.invoker is invoke,
        "production_business_collector": rechecks.collector is run_business_readiness,
        "worker_disabled": not settings.defense_worker_enabled,
        "stopped": False,
        "graceful_shutdown": False,
    }
    previous_send = httpx.AsyncClient.send

    async def no_model(*args, **kwargs):
        counts["model_attempts"] += 1
        return await previous_send(*args, **kwargs)

    httpx.AsyncClient.send = no_model

    @app.middleware("http")
    async def count_requests(request, call_next):
        if request.method in {"GET", "HEAD"}:
            counts["read_requests"] += 1
        else:
            path = request.url.path
            operation = "mode" if path == "/api/automation" else path.rsplit("/", 1)[-1]
            require(
                operation in {"mode", "arm", "prepare", "apply", "query", "revoke", "rechecks"},
                "unexpected_write_route",
            )
            counts["write_requests"][operation] = counts["write_requests"].get(operation, 0) + 1
        return await call_next(request)

    store, original = controller.store, controller.store.record_unavailable

    def unavailable(rid, op, **options):
        error = sys.exception()
        if op != "apply" or not isinstance(error, UnknownDefenseResult):
            return original(rid, op, **options)
        require(error.request_id == rid and error.query_required, "unknown_request_changed")
        transaction, metadata = store.transaction(rid), store.request_metadata(rid, "apply")
        approval, usage = store.approval_record(rid, "apply"), store.execution_usage(rid)
        require(
            transaction.kind == "action"
            and transaction.phase == "apply_sendable"
            and transaction.query_required
            and metadata.dispatch_phase == "sendable"
            and metadata.send_owner == transaction.owner
            and metadata.send_started_at is not None
            and metadata.reply_sha256 is None
            and approval is not None
            and approval.dispatch_state == "used"
            and usage is not None
            and usage.state == "consumed"
            and not any(row.op == "apply" for row in store.observations(rid))
            and counts["write_requests"].get("apply") == 1,
            "crash_boundary_not_closed",
        )
        marker = {
            "schema": "opsark-abrupt-apply-boundary/v1",
            "boundary": BOUNDARY,
            "request_ref_sha256": hashlib.sha256(rid.encode("ascii")).hexdigest(),
            "request_sha256": metadata.request_sha256,
            "dispatch_phase": metadata.dispatch_phase,
            "reply_committed": False,
            "unavailable_observation_committed": False,
            "approval_state": "used",
            "usage_state": "consumed",
            "client_result": "post_dispatch_result_unknown",
            "actual_socket_fault_independently_required": True,
            "expected_exit_code": EXIT_CODE,
        }
        audit = {
            **counts,
            "termination_kind": "os_exit",
            "boundary": marker,
            "expected_exit_code": EXIT_CODE,
        }
        _durable_json(Path(payload["audit"]).parent / "apply-crash-marker.json", marker)
        _durable_json(Path(payload["audit"]), audit)
        os._exit(EXIT_CODE)

    store.record_unavailable = unavailable
    return app


class AbruptProcess(live.LiveProcess):
    """An expected os._exit is verified using the original creation-bound handle."""

    def _command(self):
        return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child-crash-apply"]

    def _finish(self, success):
        if not success:
            return super()._finish(False)
        require(self.process is not None and self.pid is not None, "crash_process_missing")
        if self.process is None:
            raise RuntimeError("crash_process_missing")
        try:
            self.process.wait(timeout=8)
            actual = self.process.returncode
            if self._runtime_handle is not None:
                import ctypes
                from ctypes import wintypes

                kernel, handle = self._runtime_handle
                require(kernel.WaitForSingleObject(handle, 8000) == 0, "runtime_not_exited")
                kernel.GetExitCodeProcess.argtypes = [
                    wintypes.HANDLE,
                    ctypes.POINTER(wintypes.DWORD),
                ]
                kernel.GetExitCodeProcess.restype = wintypes.BOOL
                code = wintypes.DWORD()
                require(kernel.GetExitCodeProcess(handle, ctypes.byref(code)), "exit_code_missing")
                actual = code.value
            require(
                self.process.returncode == actual == EXIT_CODE
                and self.audit_path.is_file()
                and not self.stop_path.exists(),
                "abrupt_exit_not_verified",
            )
            self.audit = json.loads(self.audit_path.read_text(encoding="ascii"))
            require(
                self.audit["pid"] == self.pid
                and self.audit["termination_kind"] == "os_exit"
                and self.audit["boundary"]["boundary"] == BOUNDARY
                and self.audit["model_attempts"] == 0
                and self.audit["worker_disabled"]
                and not self.audit["stopped"]
                and not self.audit["graceful_shutdown"],
                "crash_audit_changed",
            )
            self.audit.update(stopped=True, actual_exit_code=actual, process_exit_verified=True)
        except subprocess.TimeoutExpired:
            self._abort_owned()
            raise RuntimeError("crash_exit_timeout") from None
        except BaseException:
            self._abort_owned()
            raise
        finally:
            if self._runtime_handle is not None:
                kernel, handle = self._runtime_handle
                kernel.CloseHandle(handle)
                self._runtime_handle = None


def _child():
    raw = sys.stdin.buffer.read(32769)
    require(len(raw) <= 32768, "child_payload_budget")
    payload = json.loads(raw)
    # The inherited fixed lifecycle reads this same stdin document once.
    sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
    with patch.object(live, "_application", lambda settings: _crash_application(settings, payload)):
        return live._child()


if __name__ == "__main__":
    require(sys.argv[1:] == ["--child-crash-apply"], "invalid_child_entry")
    raise SystemExit(_child())
