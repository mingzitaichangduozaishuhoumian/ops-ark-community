"""One explicitly approved, exact container restart with durable read-only reconciliation."""

import builtins
import hashlib
import re
import secrets
import sqlite3
from collections.abc import Callable
from contextlib import closing, contextmanager, suppress
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import AwareDatetime, Field, field_validator, model_validator

from opsark.baselines import scope_for
from opsark.container_restart_client import invoke
from opsark.handoff_timeline import report_matches_handoff_scope
from opsark.models import HostPreflightRequest, Report, StrictModel
from opsark.nginx_action_client import NginxActionTransportError, canonical
from opsark.nginx_dependencies import ContainerRestartImpact, dependency_binding_digest

PlanId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Revision = Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
HostId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
ReportId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
ReceiptSource = Literal["submit", "status", "reconcile_status", "observe"]
Reason = Literal[
    "policy_refused",
    "scope_changed",
    "expired",
    "busy",
    "conflict",
    "not_found",
    "operation_unconfirmed",
]
IMPACT = {"expected_downtime_seconds": None, "no_recreate": True, "no_volume_changes": True}


def _utc(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() != UTC.utcoffset(result):
        raise ValueError("容器重启预览时间格式不受支持。")
    return result


def _action_id(plan_id):
    return hashlib.sha256(
        canonical({"domain": "opsark-container-restart-v1", "plan_id": plan_id})
    ).hexdigest()


class Prepare(StrictModel):
    host_id: HostId
    expected_mode_revision: Revision
    report_id: ReportId | None = None


class Approve(StrictModel):
    expected_plan_digest: Digest
    expected_mode_revision: Revision
    confirm: Literal[True]

    @field_validator("confirm", mode="before")
    @classmethod
    def exact_confirmation(cls, value):
        if value is not True:
            raise ValueError("需要明确批准此次容器重启。")
        return value


class _Plan(StrictModel):
    schema_version: Literal[1]
    status: Literal["ready"]
    policy_digest: Digest
    plan_id: PlanId
    action_id: Digest
    plan_digest: Digest
    mode_revision: Revision
    container_id: Digest
    image_id: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    expires_at: Annotated[str, Field(max_length=40)]

    @model_validator(mode="after")
    def exact_plan(self):
        _utc(self.expires_at)
        if self.action_id != _action_id(self.plan_id):
            raise ValueError("容器重启预览与原任务标识不一致。")
        return self


class _Unavailable(StrictModel):
    schema_version: Literal[1]
    status: Literal["missing", "refused"]
    policy_digest: Digest
    plan_id: PlanId
    reason: Reason


class _Receipt(StrictModel):
    schema_version: Literal[1]
    status: Literal["missing", "refused", "verified", "unknown", "not_started"]
    policy_digest: Digest
    action_id: Digest
    plan_id: PlanId | None
    plan_digest: Digest | None
    mode_revision: Revision | None
    reason: Reason | None
    reconciliation_status: Literal["verified"] | None

    @model_validator(mode="after")
    def closed(self):
        bindings = (self.plan_id, self.plan_digest, self.mode_revision)
        if (
            (self.status == "missing" and any(item is not None for item in bindings))
            or (self.status != "missing" and any(item is None for item in bindings))
            or (self.status == "verified" and self.reason is not None)
            or (self.status == "not_started" and self.reason != "expired")
            or (self.reconciliation_status is not None and self.status != "unknown")
        ):
            raise ValueError("容器重启回执字段不一致。")
        return self


class _Handoff(StrictModel):
    """Internal binding only. Customer renderers must omit its identifiers and digests."""

    report_id: ReportId
    host_id: HostId
    host_scope: Digest
    target_scope: Digest
    plan_id: PlanId
    action_id: Digest
    approval_id: PlanId
    approved_at: AwareDatetime
    receipt_observed_at: AwareDatetime | None
    receipt_source: ReceiptSource | None
    operation_status: Literal["verified", "unknown", "not_started"]
    reconciliation_status: Literal["verified"] | None
    blocking: bool


def _version(raw):
    if type(raw) is not dict or type(raw.get("schema_version")) is not int:
        raise ValueError("容器重启回执版本无效。")


def _check_plan(plan, row):
    if any(
        getattr(plan, key) != row[key]
        for key in ("plan_id", "mode_revision", "policy_digest", "container_id")
    ):
        raise ValueError("容器重启预览和原登记不一致。")
    return plan


def _check_receipt(receipt, plan):
    if (
        receipt.policy_digest != plan.policy_digest
        or receipt.action_id != plan.action_id
        or (
            receipt.status != "missing"
            and any(
                getattr(receipt, key) != getattr(plan, key)
                for key in ("plan_id", "plan_digest", "mode_revision")
            )
        )
    ):
        raise ValueError("容器重启回执和原批准不一致。")
    return receipt


_DDL = """
CREATE TABLE IF NOT EXISTS container_restarts (
    plan_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    target_scope TEXT NOT NULL,
    transport_scope TEXT NOT NULL,
    container_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    mode_revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    plan_json TEXT,
    receipt_json TEXT,
    refusal_json TEXT,
    approval_id TEXT
)
"""

_HANDOFF_DDL = """
CREATE TABLE IF NOT EXISTS container_restart_handoff (
    plan_id TEXT PRIMARY KEY NOT NULL,
    report_id TEXT NOT NULL,
    host_scope TEXT NOT NULL,
    link_sha256 TEXT NOT NULL,
    approved_at TEXT,
    receipt_observed_at TEXT,
    receipt_source TEXT
)
"""
_HANDOFF_REPORT_DDL = """
CREATE INDEX IF NOT EXISTS container_handoff_report_approved ON container_restart_handoff
    (report_id, approved_at DESC, plan_id DESC) WHERE approved_at IS NOT NULL
"""


def _handoff_link(row, report_id, host_scope):
    return hashlib.sha256(
        canonical(
            {
                "domain": "opsark-container-restart-handoff/v1",
                "report_id": report_id,
                "host_scope": host_scope,
                **{key: row[key] for key in ("plan_id", "host_id", "target_scope", "created_at")},
            }
        )
    ).hexdigest()


class ContainerRestartService:
    def __init__(
        self,
        targets,
        automation,
        *,
        invoker=invoke,
        clock=None,
        resolve_report: Callable[[str], Report | None] | None = None,
    ):
        self.targets = dict(targets)
        self.automation = automation
        self.invoker = invoker
        self.clock = clock or (lambda: datetime.now(UTC))
        self.resolve_report = resolve_report
        if self.targets:
            with self._database(write=True) as db:
                db.execute(_DDL)
                db.execute(_HANDOFF_DDL)
                db.execute(_HANDOFF_REPORT_DDL)

    @contextmanager
    def _database(self, *, write=False):
        # Commit approval in the same database transaction as the current mode check.
        with closing(sqlite3.connect(self.automation.path, timeout=5)) as db, db:
            db.row_factory = sqlite3.Row
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db

    @staticmethod
    def _table(db):
        return (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='container_restarts'"
            ).fetchone()
            is not None
        )

    def _row(self, db, plan_id):
        if self._table(db):
            row = db.execute(
                "SELECT * FROM container_restarts WHERE plan_id=?", (plan_id,)
            ).fetchone()
            if row is not None:
                return dict(row)
        raise HTTPException(404, "原容器重启计划不存在。")

    @staticmethod
    def _handoff_row(db, plan_id):
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='container_restart_handoff'"
        ).fetchone()
        if exists is None:
            return None
        return db.execute(
            "SELECT * FROM container_restart_handoff WHERE plan_id=?", (plan_id,)
        ).fetchone()

    def _mode(self, db, revision, *, approve):
        current = db.execute(
            "SELECT scope,mode,revision,sync_revision,sync_error FROM automation_mode WHERE id=1"
        ).fetchone()
        if (
            current is None
            or current["scope"] != self.automation.scope
            or current["mode"] not in ({"assisted"} if approve else {"manual", "assisted"})
            or current["revision"] != revision
            or (
                self.automation.sync_required
                and (current["sync_revision"] != revision or current["sync_error"] is not None)
            )
        ):
            raise HTTPException(409, "模式版本已改变，执行只接受半自动模式下的明确批准。")

    def _target(self, host_id, row=None):
        target = self.targets.get(host_id)
        if target is None or (row is not None and target.target_scope != row["target_scope"]):
            raise HTTPException(403, "该主机未登记当前容器重启权限。")
        return target

    @staticmethod
    def _check_pending(db):
        # First release has one write target. Keep old unknown work fenced after alias changes.
        if db.execute(
            "SELECT 1 FROM container_restarts WHERE state='submitting' LIMIT 1"
        ).fetchone():
            raise HTTPException(409, "仍有待对账的原容器重启。")

    @staticmethod
    def _plan(row):
        return (
            _check_plan(_Plan.model_validate_json(row["plan_json"]), row)
            if row["plan_json"]
            else None
        )

    def _view(self, row):
        plan = self._plan(row)
        receipt = None
        if row["receipt_json"]:
            if plan is None:
                raise ValueError("容器重启回执缺少原预览。")
            receipt = _check_receipt(_Receipt.model_validate_json(row["receipt_json"]), plan)
        refusal = (
            _Unavailable.model_validate_json(row["refusal_json"]) if row["refusal_json"] else None
        )
        status = {
            "preparing": "prepare_pending",
            "prepared": "ready",
            "prepare_refused": "refused",
            "submitting": "unknown",
            "finished": "unknown",
        }[row["state"]]
        return {
            "plan_id": row["plan_id"],
            "host_id": row["host_id"],
            "binding_digest": row["target_scope"],
            "status": receipt.status if receipt else status,
            "created_at": row["created_at"],
            "approved": row["approval_id"] is not None,
            "blocking": row["state"] == "submitting",
            "plan": {**plan.model_dump(mode="json"), "impact": dict(IMPACT)} if plan else None,
            "receipt": receipt.model_dump(mode="json") if receipt else None,
            "prepare_reason": refusal.reason if refusal else None,
        }

    def list(self):
        with self._database() as db:
            if not self._table(db):
                return []
            rows = db.execute(
                "SELECT * FROM container_restarts ORDER BY created_at DESC,plan_id LIMIT 50"
            ).fetchall()
        return [self._view(dict(row)) for row in rows]

    def handoff_plan_ids(self, report_id: str) -> builtins.list[str]:
        with self._database() as db:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='container_restart_handoff'"
            ).fetchone():
                return []
            return [
                row["plan_id"]
                for row in db.execute(
                    "SELECT plan_id FROM container_restart_handoff WHERE report_id=? "
                    "AND approved_at IS NOT NULL ORDER BY approved_at DESC,plan_id DESC LIMIT 20",
                    (report_id,),
                )
            ]

    def read_handoff(self, plan_id: str) -> dict | None:
        """Read validated local history without a current target, SSH or ledger writes."""
        if not re.fullmatch(r"[0-9a-f]{32}", plan_id):
            raise ValueError("容器重启交接编号无效。")
        with self._database() as db:
            db.execute("BEGIN")
            row = self._row(db, plan_id)
            binding = self._handoff_row(db, plan_id)
        if binding is None:
            return None
        if binding["link_sha256"] != _handoff_link(
            row, binding["report_id"], binding["host_scope"]
        ):
            raise ValueError("容器重启交接登记与原计划不一致。")
        if row["approval_id"] is None:
            if any(
                binding[key] is not None
                for key in ("approved_at", "receipt_observed_at", "receipt_source")
            ):
                raise ValueError("容器重启交接记录与原批准不一致。")
            return None
        plan = self._plan(row)
        observed, source = binding["receipt_observed_at"], binding["receipt_source"]
        receipt = (
            _check_receipt(_Receipt.model_validate_json(row["receipt_json"]), plan)
            if plan is not None and row["receipt_json"] is not None
            else None
        )
        accepted = receipt is not None
        if (
            plan is None
            or type(binding["approved_at"]) is not str
            or accepted != (row["receipt_json"] is not None)
            or accepted != (observed is not None)
            or accepted != (source is not None)
            or (accepted and type(observed) is not str)
        ):
            raise ValueError("容器重启交接记录缺少原批准或接收时间。")
        approved = _utc(binding["approved_at"])
        receipt_time = _utc(observed) if accepted else None
        blocking = row["state"] == "submitting"
        operation_status = receipt.status if receipt is not None else "unknown"
        reconciliation = receipt.reconciliation_status if receipt is not None else None
        terminal = operation_status in {"verified", "not_started"} or reconciliation == "verified"
        if (
            not _utc(row["created_at"]) <= approved < _utc(plan.expires_at)
            or (receipt_time is not None and receipt_time < approved)
            or row["state"] != ("finished" if terminal else "submitting")
            or (
                operation_status == "not_started"
                and (
                    source != "reconcile_status"
                    or receipt_time is None
                    or receipt_time < _utc(plan.expires_at)
                )
            )
        ):
            raise ValueError("容器重启交接记录与原状态或时间不一致。")
        return _Handoff(
            report_id=binding["report_id"],
            host_id=row["host_id"],
            host_scope=binding["host_scope"],
            target_scope=row["target_scope"],
            plan_id=plan.plan_id,
            action_id=plan.action_id,
            approval_id=row["approval_id"],
            approved_at=approved,
            receipt_observed_at=receipt_time,
            receipt_source=source,
            operation_status=operation_status,
            reconciliation_status=reconciliation,
            blocking=blocking,
        ).model_dump(mode="json")

    def _save_plan(self, row, raw):
        _version(raw)
        if raw.get("status") == "ready":
            plan = _check_plan(_Plan.model_validate(raw), row)
            state, plan_json, refusal_json = "prepared", plan.model_dump_json(), None
        else:
            reply = _Unavailable.model_validate(raw)
            if reply.plan_id != row["plan_id"] or reply.policy_digest != row["policy_digest"]:
                raise ValueError("容器重启预览回执与原请求不一致。")
            if reply.status == "missing":
                return row
            state, plan_json, refusal_json = "prepare_refused", None, reply.model_dump_json()
        with self._database(write=True) as db:
            db.execute(
                "UPDATE container_restarts SET state=?,plan_json=?,refusal_json=? "
                "WHERE plan_id=? AND state='preparing'",
                (state, plan_json, refusal_json, row["plan_id"]),
            )
            return self._row(db, row["plan_id"])

    def prepare(self, body):
        target = self._target(body.host_id)
        report = None
        host_scope = None
        if body.report_id is not None:
            report = self.resolve_report(body.report_id) if self.resolve_report else None
            if report is None:
                raise HTTPException(404, "原调查报告不存在。")
            host_scope = scope_for(target.host.public)
            if (
                report.id != body.report_id
                or report.target is None
                or not report_matches_handoff_scope(report, body.host_id, host_scope)
            ):
                raise HTTPException(409, "原调查报告与容器重启范围不一致。")
        plan_id = secrets.token_hex(16)
        with self._database(write=True) as db:
            self._mode(db, body.expected_mode_revision, approve=False)
            self._check_pending(db)
            created_at = self.clock()
            if report is not None and (
                report.created_at.utcoffset() is None or report.created_at > created_at
            ):
                raise HTTPException(409, "原调查报告时间未能核实。")
            db.execute(
                "INSERT INTO container_restarts (plan_id,host_id,target_scope,transport_scope,"
                "container_id,policy_digest,mode_revision,state,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    plan_id,
                    body.host_id,
                    target.target_scope,
                    target.transport_scope,
                    target.container_id,
                    target.policy_digest,
                    body.expected_mode_revision,
                    "preparing",
                    created_at.isoformat(),
                ),
            )
            row = self._row(db, plan_id)
            if report is not None:
                db.execute(
                    "INSERT INTO container_restart_handoff "
                    "(plan_id,report_id,host_scope,link_sha256) VALUES (?,?,?,?)",
                    (plan_id, report.id, host_scope, _handoff_link(row, report.id, host_scope)),
                )
        with suppress(NginxActionTransportError, ValueError, OSError):
            row = self._save_plan(
                row,
                self.invoker(
                    target, "prepare", plan_id=plan_id, mode_revision=row["mode_revision"]
                ),
            )
        return self._view(row)

    def _save_receipt(self, plan, raw, *, source: ReceiptSource):
        _version(raw)
        receipt = _check_receipt(_Receipt.model_validate(raw), plan)
        observed_at = self.clock()
        if receipt.status == "not_started" and (
            source != "reconcile_status" or observed_at < _utc(plan.expires_at)
        ):
            raise ValueError("容器重启尚无已关闭的未开始凭证。")
        terminal = (
            receipt.status in {"verified", "not_started"}
            or receipt.reconciliation_status == "verified"
        )
        with self._database(write=True) as db:
            binding = self._handoff_row(db, plan.plan_id)
            if binding is not None and (
                binding["approved_at"] is None
                or observed_at < _utc(binding["approved_at"])
                or (
                    binding["receipt_observed_at"] is not None
                    and observed_at < _utc(binding["receipt_observed_at"])
                )
            ):
                raise ValueError("容器重启交接回执时间早于原记录。")
            if receipt.status in {"verified", "unknown", "not_started"}:
                updated = db.execute(
                    "UPDATE container_restarts SET state=?,receipt_json=? "
                    "WHERE plan_id=? AND state='submitting'",
                    (
                        "finished" if terminal else "submitting",
                        receipt.model_dump_json(),
                        plan.plan_id,
                    ),
                )
                if updated.rowcount and binding is not None:
                    db.execute(
                        "UPDATE container_restart_handoff "
                        "SET receipt_observed_at=?,receipt_source=? WHERE plan_id=?",
                        (observed_at.isoformat(), source, plan.plan_id),
                    )
            return self._row(db, plan.plan_id)

    def approve(self, plan_id, body):
        with self._database(write=True) as db:
            row = self._row(db, plan_id)
            plan = self._plan(row)
            if (
                plan is None
                or plan.plan_digest != body.expected_plan_digest
                or plan.mode_revision != body.expected_mode_revision
            ):
                raise HTTPException(409, "批准摘要或模式修订与原预览不一致。")
            if row["state"] != "prepared":
                return self._view(row)
            target = self._target(row["host_id"], row)
            self._mode(db, body.expected_mode_revision, approve=True)
            self._check_pending(db)
            approved_at = self.clock()
            if approved_at >= _utc(plan.expires_at):
                raise HTTPException(409, "容器重启预览已过期。")
            binding = self._handoff_row(db, plan_id)
            if binding is not None and approved_at < _utc(row["created_at"]):
                raise HTTPException(409, "容器重启批准时间早于原预览。")
            approval_id = secrets.token_hex(16)
            db.execute(
                "UPDATE container_restarts SET state='submitting',approval_id=? WHERE plan_id=?",
                (approval_id, plan_id),
            )
            if binding is not None:
                db.execute(
                    "UPDATE container_restart_handoff SET approved_at=? WHERE plan_id=?",
                    (approved_at.isoformat(), plan_id),
                )
            row = self._row(db, plan_id)
        with suppress(NginxActionTransportError, ValueError, OSError):
            row = self._save_receipt(
                plan,
                self.invoker(
                    target,
                    "submit",
                    plan_id=plan_id,
                    action_id=plan.action_id,
                    plan_digest=plan.plan_digest,
                    approval_id=approval_id,
                    mode_revision=plan.mode_revision,
                ),
                source="submit",
            )
        return self._view(row)

    def get(self, plan_id):
        with self._database() as db:
            row = self._row(db, plan_id)
        target = self.targets.get(row["host_id"])
        if target is None or target.transport_scope != row["transport_scope"]:
            return self._view(row)
        policy = row["policy_digest"]
        try:
            if row["state"] == "preparing":
                row = self._save_plan(
                    row, self.invoker(target, "plan_status", policy_digest=policy, plan_id=plan_id)
                )
            elif row["state"] == "submitting":
                plan = self._plan(row)
                if plan is None:
                    raise ValueError("已批准的容器重启缺少原预览。")
                expired = self.clock() >= _utc(plan.expires_at)
                fields = {"action_id": plan.action_id}
                if expired:
                    fields.update(
                        plan_id=plan_id,
                        plan_digest=plan.plan_digest,
                        mode_revision=plan.mode_revision,
                    )
                source = "reconcile_status" if expired else "status"
                raw = self.invoker(
                    target,
                    source,
                    policy_digest=policy,
                    **fields,
                )
                row = self._save_receipt(plan, raw, source=source)
        except (NginxActionTransportError, ValueError, OSError):
            pass
        return self._view(row)

    def _impact_plan(self, plan_id):
        with self._database() as db:
            row = self._row(db, plan_id)
            plan = self._plan(row)
            if plan is None or row["state"] != "prepared" or self.clock() >= _utc(plan.expires_at):
                raise HTTPException(409, "影响检查需要有效的待批准原预览。")
            self._mode(db, plan.mode_revision, approve=False)
            target = self._target(row["host_id"], row)
            binding = target.container_id, target.policy_digest
            if binding != (plan.container_id, plan.policy_digest):
                raise HTTPException(409, "容器重启登记与原预览不一致。")
        return target, plan

    def impact(self, plan_id, collect):
        target, plan = self._impact_plan(plan_id)
        binding_digest = dependency_binding_digest(target.host)
        observation = collect(target.host, plan.container_id)
        if self._impact_plan(plan_id) != (target, plan):
            raise HTTPException(409, "容器重启预览在观察期间已变更。")
        return _ImpactResponse(
            plan_id=plan_id, binding_digest=binding_digest, **observation.model_dump()
        )

    def observe(self, plan_id):
        with self._database() as db:
            row = self._row(db, plan_id)
        target = self._target(row["host_id"], row)
        plan = self._plan(row)
        if row["state"] != "submitting" or plan is None:
            raise HTTPException(409, "只有待对账的原容器重启可运行只读复验。")
        with suppress(NginxActionTransportError, ValueError, OSError):
            row = self._save_receipt(
                plan, self.invoker(target, "observe", action_id=plan.action_id), source="observe"
            )
        return self._view(row)


class _ImpactResponse(ContainerRestartImpact):
    plan_id: PlanId
    binding_digest: Digest | None

    @model_validator(mode="after")
    def check_binding(self) -> "_ImpactResponse":
        if self.status == "observed" and self.binding_digest is None:
            raise ValueError("Observation requires a registered dependency binding")
        return self


def register_container_restart_routes(application, service, protected, *, collect_impact):
    def guarded(call):
        try:
            return call()
        except (ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, "容器重启原记录暂时无法核实。") from None

    @application.get("/api/container-restarts", dependencies=protected)
    def listed():
        return guarded(service.list)

    @application.post("/api/container-restarts/prepare", dependencies=protected)
    def prepare(body: Prepare):
        return guarded(lambda: service.prepare(body))

    @application.get("/api/container-restarts/{plan_id}", dependencies=protected)
    def status(plan_id: PlanId):
        return guarded(lambda: service.get(plan_id))

    @application.post(
        "/api/container-restarts/{plan_id}/impact",
        dependencies=protected,
        response_model=_ImpactResponse,
    )
    def impact(plan_id: PlanId, _body: HostPreflightRequest):
        return guarded(lambda: service.impact(plan_id, collect_impact))

    @application.post("/api/container-restarts/{plan_id}/approve", dependencies=protected)
    def approve(plan_id: PlanId, body: Approve):
        return guarded(lambda: service.approve(plan_id, body))

    @application.post("/api/container-restarts/{plan_id}/observe", dependencies=protected)
    def observe(plan_id: PlanId):
        return guarded(lambda: service.observe(plan_id))
