"""Preview, approve and reconcile an administrator-registered Nginx change."""

import hashlib
import json
import re
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import ConfigDict, Field, field_validator, model_validator

from opsark.baselines import scope_for
from opsark.control_modes import Digest, HostIdentifier
from opsark.handoff_timeline import report_matches_handoff_scope
from opsark.models import Report, StrictModel
from opsark.nginx_action_client import (
    NginxActionTransportError,
    _nonfinite,
    _unique,
    canonical,
    invoke,
)

PlanId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Revision = Annotated[int, Field(ge=0, le=2**63 - 1)]
SiteId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]
Endpoint = Annotated[str, Field(pattern=r"^127\.0\.0\.1:[1-9][0-9]{0,4}$")]
Action = Literal["apply", "restore"]
Reason = Literal[
    "policy_refused",
    "scope_changed",
    "syntax_refused",
    "expired",
    "busy",
    "business_unconfirmed",
    "conflict",
    "not_found",
    "operation_unconfirmed",
]
_PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVATION_SOURCES = {"submit", "status", "reconcile_status", "observe"}


class _Closed(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Prepare(_Closed):
    host_id: HostIdentifier
    expected_mode_revision: Revision
    report_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")] | None = None


class PrepareRestore(_Closed):
    expected_mode_revision: Revision


class Approve(_Closed):
    expected_plan_digest: Digest
    expected_mode_revision: Revision
    confirm: Literal[True]

    @field_validator("confirm", mode="before")
    @classmethod
    def explicit_confirmation(cls, value):
        if value is not True:
            raise ValueError("必须明确批准这份 Nginx 变更预览。")
        return value


def _utc(value):
    if not isinstance(value, str):
        raise ValueError("Nginx 处置时间格式无效。")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("Nginx 处置时间必须为 UTC。")
    return parsed.astimezone(UTC)


def _action_id(plan_id, action):
    return hashlib.sha256(
        canonical(
            {
                "domain": "opsark-nginx-action-v1",
                "plan_id": plan_id,
                "action": action,
            }
        )
    ).hexdigest()


class _Plan(_Closed):
    schema_version: Literal[1]
    status: Literal["ready"]
    plan_id: PlanId
    action: Action
    action_id: Digest
    policy_digest: Digest
    plan_digest: Digest
    mode_revision: Revision
    source_sha256: Digest
    candidate_sha256: Digest
    backup_sha256: Digest
    context_sha256: Digest
    expires_at: Annotated[str, Field(max_length=40)]
    upstream_before: Endpoint
    upstream_after: Endpoint
    affected_site_ids: list[SiteId] = Field(min_length=1, max_length=8)
    syntax: Literal["passed"]
    original_action_id: Digest | None

    @model_validator(mode="after")
    def bound(self):
        _utc(self.expires_at)
        if (
            self.action_id != _action_id(self.plan_id, self.action)
            or self.source_sha256 == self.candidate_sha256
            or self.upstream_before == self.upstream_after
            or any(
                int(endpoint.rsplit(":", 1)[1]) > 65535
                for endpoint in (self.upstream_before, self.upstream_after)
            )
            or len(set(self.affected_site_ids)) != len(self.affected_site_ids)
            or (
                self.action == "apply"
                and (
                    self.original_action_id is not None or self.backup_sha256 != self.source_sha256
                )
            )
            or (
                self.action == "restore"
                and (self.original_action_id is None or self.backup_sha256 != self.candidate_sha256)
            )
        ):
            raise ValueError("Nginx 预览绑定不一致。")
        return self


class _PlanUnavailable(_Closed):
    schema_version: Literal[1]
    status: Literal["missing", "refused"]
    policy_digest: Digest
    plan_id: PlanId
    reason: Reason | None


class _Receipt(_Closed):
    schema_version: Literal[1]
    status: Literal["missing", "unknown", "verified", "refused", "not_started"]
    action_id: Digest
    action: Action | None
    policy_digest: Digest
    plan_id: PlanId | None
    plan_digest: Digest | None
    mode_revision: Revision | None
    reason: Reason | None
    reconciliation_status: (
        Literal["verified", "disk_published_live_previous", "unchanged_from_preview"] | None
    )

    @model_validator(mode="after")
    def bound(self):
        binding = (self.action, self.plan_id, self.plan_digest, self.mode_revision)
        if self.status == "missing":
            if any(item is not None for item in binding) or self.reconciliation_status is not None:
                raise ValueError("缺失回执不能携带执行凭证。")
        elif any(item is None for item in binding):
            raise ValueError("处置回执缺少原批准绑定。")
        if (
            (self.status == "verified" and self.reason is not None)
            or (self.status == "not_started" and self.reason != "expired")
            or (self.reconciliation_status is not None and self.status != "unknown")
            or (
                self.reconciliation_status == "disk_published_live_previous"
                and self.action != "apply"
            )
        ):
            raise ValueError("处置回执状态不一致。")
        return self


def _version(raw):
    if type(raw) is not dict or type(raw.get("schema_version")) is not int:
        raise ValueError("Nginx 处置响应版本无效。")


def _stored(raw):
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)


def _plan(raw, record):
    _version(raw)
    value = _Plan.model_validate(raw)
    if (
        value.policy_digest != record["policy_digest"]
        or value.plan_id != record["plan_id"]
        or value.action != record["action"]
        or value.mode_revision != record["mode_revision"]
        or value.original_action_id != record["original_action_id"]
    ):
        raise ValueError("预览响应与原请求不一致。")
    return value


def _receipt(raw, record, plan):
    _version(raw)
    value = _Receipt.model_validate(raw)
    if value.policy_digest != record["policy_digest"] or value.action_id != plan.action_id:
        raise ValueError("处置响应与原任务不一致。")
    if value.status != "missing" and (
        value.plan_id != plan.plan_id
        or value.plan_digest != plan.plan_digest
        or value.action != plan.action
        or value.mode_revision != plan.mode_revision
    ):
        raise ValueError("处置响应与原批准不一致。")
    return value


_DDL = """
CREATE TABLE IF NOT EXISTS nginx_managed_actions (
    plan_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    transport_scope TEXT NOT NULL,
    target_scope TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    mode_revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    original_action_id TEXT,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    plan_json TEXT,
    plan_refusal_json TEXT,
    approval_id TEXT,
    receipt_json TEXT
)
"""

_HANDOFF_DDL = """
CREATE TABLE IF NOT EXISTS nginx_action_handoff (
    plan_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    host_scope TEXT NOT NULL,
    link_sha256 TEXT NOT NULL,
    approved_at TEXT,
    receipt_observed_at TEXT,
    receipt_source TEXT
)
"""

_HANDOFF_RESTORE_INDEX = "nginx_handoff_approved_restore"
_HANDOFF_RESTORE_DDL = """
CREATE INDEX IF NOT EXISTS nginx_handoff_approved_restore ON nginx_managed_actions
    (original_action_id, created_at DESC, plan_id DESC)
    WHERE action='restore' AND approval_id IS NOT NULL
"""
_HANDOFF_REPORT_DDL = """
CREATE INDEX IF NOT EXISTS nginx_handoff_report_approved ON nginx_action_handoff
    (report_id, approved_at DESC, plan_id DESC) WHERE approved_at IS NOT NULL
"""


def _handoff_link(record, report_id, host_scope):
    return hashlib.sha256(
        canonical(
            {
                "domain": "opsark-nginx-action-handoff/v1",
                "report_id": report_id,
                "host_scope": host_scope,
                **{
                    key: record[key]
                    for key in (
                        "plan_id",
                        "host_id",
                        "target_scope",
                        "action",
                        "original_action_id",
                        "created_at",
                    )
                },
            }
        )
    ).hexdigest()


class NginxActionService:
    def __init__(self, targets, automation, *, invoker=invoke, clock=None, resolve_report=None):
        self.targets = dict(targets)
        self.automation = automation
        self.invoker = invoker
        self.clock = clock or (lambda: datetime.now(UTC))
        self.resolve_report = resolve_report
        if self.targets:
            with self._database(write=True) as db:
                db.execute(_DDL)
                db.execute(_HANDOFF_DDL)
                db.execute(_HANDOFF_RESTORE_DDL)
                db.execute(_HANDOFF_REPORT_DDL)

    @contextmanager
    def _database(self, *, write=False):
        # The mode row and approval intent share one SQLite write transaction.
        with closing(sqlite3.connect(self.automation.path, timeout=5)) as db, db:
            db.row_factory = sqlite3.Row
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db

    @staticmethod
    def _table(db):
        return (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nginx_managed_actions'"
            ).fetchone()
            is not None
        )

    @classmethod
    def _record(cls, db, plan_id):
        if not _PLAN_ID.fullmatch(plan_id) or not cls._table(db):
            raise HTTPException(404, "Nginx 原计划不存在。")
        row = db.execute(
            "SELECT * FROM nginx_managed_actions WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Nginx 原计划不存在。")
        return dict(row)

    def _current_mode(self, db, revision, *, approving):
        row = db.execute(
            "SELECT scope,mode,revision,sync_revision,sync_error FROM automation_mode WHERE id=1"
        ).fetchone()
        allowed = {"assisted"} if approving else {"manual", "assisted"}
        if (
            row is None
            or row["scope"] != self.automation.scope
            or row["mode"] not in allowed
            or row["revision"] != revision
            or (
                self.automation.sync_required
                and (row["sync_revision"] != revision or row["sync_error"] is not None)
            )
        ):
            raise HTTPException(409, "处置要求当前模式修订一致，执行仅接受半自动明确批准。")

    def _target(self, host_id, record=None):
        target = self.targets.get(host_id)
        if target is None or (record is not None and target.target_scope != record["target_scope"]):
            raise HTTPException(403, "该主机没有当前有效的 Nginx 处置登记。")
        return target

    def _pending_original(self, db, host_id, restore_original_action_id=None):
        rows = db.execute(
            "SELECT * FROM nginx_managed_actions WHERE host_id=? AND state='submitting' LIMIT 2",
            (host_id,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) == 1 and restore_original_action_id is not None:
            record = dict(rows[0])
            plan = self._saved_plan(record)
            receipt = self._saved_receipt(record, plan)
            if (
                plan is not None
                and plan.action_id == restore_original_action_id
                and receipt is not None
                and receipt.reconciliation_status == "disk_published_live_previous"
            ):
                return record
        raise HTTPException(409, "该主机有待核实的原处置，请先查询和复验原任务。")

    @staticmethod
    def _saved_plan(record):
        return _plan(_stored(record["plan_json"]), record) if record["plan_json"] else None

    @staticmethod
    def _saved_receipt(record, plan):
        if record["receipt_json"] is None:
            return None
        if plan is None:
            raise ValueError("处置回执缺少预览。")
        return _receipt(_stored(record["receipt_json"]), record, plan)

    def _view(self, record):
        plan = self._saved_plan(record)
        result = self._saved_receipt(record, plan)
        refusal = None
        if record["plan_refusal_json"]:
            raw = _stored(record["plan_refusal_json"])
            _version(raw)
            refusal = _PlanUnavailable.model_validate(raw)
            if (
                refusal.status != "refused"
                or refusal.plan_id != record["plan_id"]
                or refusal.policy_digest != record["policy_digest"]
            ):
                raise ValueError("预览拒绝与原计划不一致。")
        if not _PLAN_ID.fullmatch(record["plan_id"]) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", record["host_id"]
        ):
            raise ValueError("已存处置目标无效。")
        state = {
            "preparing": "prepare_pending",
            "prepared": "ready",
            "prepare_refused": "refused",
            "submitting": "unknown",
            "finished": "unknown",
        }[record["state"]]
        return {
            "plan_id": record["plan_id"],
            "host_id": record["host_id"],
            "status": result.status if result else state,
            "created_at": _utc(record["created_at"]).isoformat(),
            "approved": record["approval_id"] is not None,
            "blocking": record["state"] == "submitting",
            "plan": plan.model_dump(mode="json") if plan else None,
            "receipt": result.model_dump(mode="json") if result else None,
            "prepare_reason": refusal.reason if refusal else None,
        }

    def list(self):
        with self._database() as db:
            if not self._table(db):
                return []
            records = db.execute(
                "SELECT * FROM nginx_managed_actions ORDER BY created_at DESC,plan_id LIMIT 50"
            ).fetchall()
        return [self._view(dict(row)) for row in records]

    @staticmethod
    def _handoff_record(db, plan_id):
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nginx_action_handoff'"
        ).fetchone()
        if exists is None:
            return None
        row = db.execute(
            "SELECT * FROM nginx_action_handoff WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def _report_binding(self, report_id, target, host_id, now):
        host_scope = scope_for(target.host.public)
        report = self.resolve_report(report_id) if self.resolve_report is not None else None
        if (
            not isinstance(report, Report)
            or report.id != report_id
            or report.target is None
            or report.created_at.tzinfo is None
            or report.created_at > now
            or not report_matches_handoff_scope(report, host_id, host_scope)
        ):
            raise HTTPException(409, "原报告与当前 Nginx 登记范围不一致。")
        return report_id, host_scope

    def read_handoff(self, plan_id):
        """Read a bounded local projection even after host deregistration."""
        with self._database() as db:
            db.execute("BEGIN")
            record = self._record(db, plan_id)
            link = self._handoff_record(db, plan_id)
        return self._project_handoff(record, link)

    def handoff_plan_ids(self, report_id):
        with self._database() as db:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nginx_action_handoff'"
            ).fetchone():
                return []
            return [
                row["plan_id"]
                for row in db.execute(
                    "SELECT plan_id FROM nginx_action_handoff WHERE report_id=? "
                    "AND approved_at IS NOT NULL ORDER BY approved_at DESC,plan_id DESC LIMIT 20",
                    (report_id,),
                )
            ]

    def read_handoff_with_restore(self, plan_id):
        """Read original and latest approved paired restore from one local snapshot.

        The third value indicates whether the restore lookup was available. Older
        ledgers can still serve history before the target has enabled the index.
        """
        with self._database() as db:
            db.execute("BEGIN")
            record = self._record(db, plan_id)
            original = self._project_handoff(record, self._handoff_record(db, plan_id))
            if original is None or original["action"] != "apply":
                return original, None, True
            if (
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
                    (_HANDOFF_RESTORE_INDEX,),
                ).fetchone()
                is None
            ):
                return original, None, False
            restore = db.execute(
                "SELECT * FROM nginx_managed_actions INDEXED BY nginx_handoff_approved_restore "
                "WHERE original_action_id=? AND action='restore' AND approval_id IS NOT NULL "
                "ORDER BY created_at DESC,plan_id DESC LIMIT 1",
                (original["action_id"],),
            ).fetchone()
            if restore is None:
                return original, None, True
            related = self._project_handoff(
                dict(restore), self._handoff_record(db, restore["plan_id"])
            )
            if related is None:
                raise ValueError("已批准的 Nginx 回退缺少原交接登记。")
            return original, related, True

    def _project_handoff(self, record, link):
        if link is None:
            return None
        if link["link_sha256"] != _handoff_link(record, link["report_id"], link["host_scope"]):
            raise ValueError("Nginx 交接登记与原计划不一致。")
        view = self._view(record)
        plan = self._saved_plan(record)
        receipt = self._saved_receipt(record, plan)
        if not view["approved"]:
            if any(
                link[key] is not None
                for key in ("approved_at", "receipt_observed_at", "receipt_source")
            ):
                raise ValueError("未批准的 Nginx 计划含交接回执。")
            return None
        approved = _utc(link["approved_at"])
        seen = (
            _utc(link["receipt_observed_at"]) if link["receipt_observed_at"] is not None else None
        )
        if (
            plan is None
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", link["report_id"] or "")
            or not _DIGEST.fullmatch(link["host_scope"] or "")
            or not _DIGEST.fullmatch(record["target_scope"] or "")
            or not _PLAN_ID.fullmatch(record["approval_id"] or "")
            or approved < _utc(record["created_at"])
            or (receipt is None) != (seen is None)
            or (seen is None and link["receipt_source"] is not None)
            or (
                seen is not None
                and (seen < approved or link["receipt_source"] not in _OBSERVATION_SOURCES)
            )
        ):
            raise ValueError("Nginx 交接记录与原任务不一致。")
        return {
            "report_id": link["report_id"],
            "host_id": record["host_id"],
            "host_scope": link["host_scope"],
            "target_scope": record["target_scope"],
            "plan_id": record["plan_id"],
            "action": plan.action,
            "action_id": plan.action_id,
            "original_action_id": plan.original_action_id,
            "approval_id": record["approval_id"],
            "approved_at": approved.isoformat(),
            "receipt_observed_at": seen.isoformat() if seen else None,
            "receipt_source": link["receipt_source"],
            "operation_status": view["status"],
            "reconciliation_status": receipt.reconciliation_status if receipt else None,
            "blocking": view["blocking"],
        }

    def _save_plan(self, record, raw):
        _version(raw)
        if raw.get("status") == "ready":
            plan = _plan(raw, record)
            state, plan_json, refusal_json = "prepared", plan.model_dump_json(), None
        else:
            reply = _PlanUnavailable.model_validate(raw)
            if reply.plan_id != record["plan_id"] or reply.policy_digest != record["policy_digest"]:
                raise ValueError("预览拒绝与原请求不一致。")
            if reply.status == "missing":
                return record
            state, plan_json, refusal_json = "prepare_refused", None, reply.model_dump_json()
        with self._database(write=True) as db:
            db.execute(
                "UPDATE nginx_managed_actions SET state=?,plan_json=?,plan_refusal_json=? "
                "WHERE plan_id=? AND state='preparing'",
                (state, plan_json, refusal_json, record["plan_id"]),
            )
            return self._record(db, record["plan_id"])

    def _prepare(self, host_id, revision, original=None, *, report_id=None):
        target = self._target(host_id, original)
        now = self.clock()
        binding = self._report_binding(report_id, target, host_id, now) if report_id else None
        plan_id = secrets.token_hex(16)
        action = "apply" if original is None else "restore"
        prior_plan = None if original is None else self._saved_plan(original)
        if original is not None and prior_plan is None:
            raise ValueError("回退缺少原变更预览。")
        original_action_id = prior_plan.action_id if prior_plan is not None else None
        with self._database(write=True) as db:
            self._current_mode(db, revision, approving=False)
            self._pending_original(db, host_id, original_action_id)
            db.execute(
                "INSERT INTO nginx_managed_actions (plan_id,host_id,transport_scope,target_scope,"
                "policy_digest,mode_revision,action,original_action_id,state,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    plan_id,
                    host_id,
                    target.transport_scope,
                    target.target_scope,
                    target.policy_digest,
                    revision,
                    action,
                    original_action_id,
                    "preparing",
                    now.isoformat(),
                ),
            )
            if original is not None:
                previous = self._handoff_record(db, original["plan_id"])
                if previous is not None:
                    binding = (previous["report_id"], previous["host_scope"])
                    if previous["link_sha256"] != _handoff_link(original, *binding):
                        raise ValueError("原 Nginx 变更的交接登记不一致。")
            record = self._record(db, plan_id)
            if binding is not None:
                db.execute(
                    "INSERT INTO nginx_action_handoff (plan_id,report_id,host_scope,link_sha256) "
                    "VALUES (?,?,?,?)",
                    (plan_id, *binding, _handoff_link(record, *binding)),
                )
        fields = {"plan_id": plan_id, "mode_revision": revision}
        if original_action_id is not None:
            fields["original_action_id"] = original_action_id
        try:
            raw = self.invoker(
                target, "prepare" if original is None else "rollback_prepare", **fields
            )
            record = self._save_plan(record, raw)
        except (NginxActionTransportError, ValueError, OSError):
            pass
        return self._view(record)

    def prepare(self, body):
        return self._prepare(body.host_id, body.expected_mode_revision, report_id=body.report_id)

    def prepare_restore(self, plan_id, body):
        with self._database() as db:
            original = self._record(db, plan_id)
        plan = self._saved_plan(original)
        result = self._saved_receipt(original, plan)
        if (
            plan is None
            or plan.action != "apply"
            or result is None
            or (
                result.status != "verified"
                and result.reconciliation_status != "verified"
                and not (
                    original["state"] == "submitting"
                    and result.reconciliation_status == "disk_published_live_previous"
                )
            )
        ):
            raise HTTPException(409, "原变更尚未验证，不能生成回退预览。")
        return self._prepare(original["host_id"], body.expected_mode_revision, original)

    def _save_receipt(self, record, plan, raw, *, source, confirm_not_started=False):
        result = _receipt(raw, record, plan)
        if result.status == "not_started" and (
            not confirm_not_started or self.clock() < _utc(plan.expires_at)
        ):
            raise ValueError("原处置尚无可信的未开始证明。")
        state = (
            "finished"
            if result.status in {"verified", "refused", "not_started"}
            or result.reconciliation_status in {"verified", "unchanged_from_preview"}
            else "submitting"
        )
        with self._database(write=True) as db:
            current = self._record(db, plan.plan_id)
            prior = self._saved_receipt(current, plan)
            if current["state"] != "submitting" or result.status == "missing":
                return current
            # A delayed SSH response cannot erase a root-recorded publication witness.
            if (
                prior is not None
                and prior.reconciliation_status == "disk_published_live_previous"
                and result.reconciliation_status != prior.reconciliation_status
            ):
                return current
            db.execute(
                "UPDATE nginx_managed_actions SET state=?,receipt_json=? WHERE plan_id=?",
                (state, result.model_dump_json(), plan.plan_id),
            )
            link = self._handoff_record(db, plan.plan_id)
            if link is not None and prior != result:
                now = self.clock()
                if (
                    source not in _OBSERVATION_SOURCES
                    or now < _utc(link["approved_at"])
                    or (link["receipt_observed_at"] and now < _utc(link["receipt_observed_at"]))
                ):
                    raise ValueError("Nginx 回执时间与原任务不一致。")
                db.execute(
                    "UPDATE nginx_action_handoff SET receipt_observed_at=?,receipt_source=? "
                    "WHERE plan_id=?",
                    (now.isoformat(), source, plan.plan_id),
                )
            if plan.action == "restore" and (
                result.status == "verified" or result.reconciliation_status == "verified"
            ):
                original = self._pending_original(db, current["host_id"], plan.original_action_id)
                if original is not None:
                    db.execute(
                        "UPDATE nginx_managed_actions SET state='finished' WHERE plan_id=?",
                        (original["plan_id"],),
                    )
            return self._record(db, plan.plan_id)

    def approve(self, plan_id, body):
        with self._database(write=True) as db:
            record = self._record(db, plan_id)
            plan = self._saved_plan(record)
            if (
                plan is None
                or plan.plan_digest != body.expected_plan_digest
                or plan.mode_revision != body.expected_mode_revision
            ):
                raise HTTPException(409, "批准摘要或模式修订与原预览不一致。")
            if record["state"] != "prepared":
                return self._view(record)
            target = self._target(record["host_id"], record)
            self._current_mode(db, body.expected_mode_revision, approving=True)
            self._pending_original(db, record["host_id"], plan.original_action_id)
            now = self.clock()
            if _utc(plan.expires_at) <= now:
                raise HTTPException(409, "原 Nginx 预览已过期。")
            approval_id = secrets.token_hex(16)
            db.execute(
                "UPDATE nginx_managed_actions SET state='submitting',approval_id=? WHERE plan_id=?",
                (approval_id, plan_id),
            )
            if self._handoff_record(db, plan_id) is not None:
                if now < _utc(record["created_at"]):
                    raise ValueError("Nginx 批准时间早于原计划。")
                db.execute(
                    "UPDATE nginx_action_handoff SET approved_at=? WHERE plan_id=?",
                    (now.isoformat(), plan_id),
                )
            record = self._record(db, plan_id)
        try:
            raw = self.invoker(
                target,
                "submit",
                plan_id=plan_id,
                action_id=plan.action_id,
                plan_digest=plan.plan_digest,
                approval_id=approval_id,
                mode_revision=plan.mode_revision,
            )
            record = self._save_receipt(record, plan, raw, source="submit")
        except (NginxActionTransportError, ValueError, OSError):
            pass
        return self._view(record)

    def get(self, plan_id):
        with self._database() as db:
            record = self._record(db, plan_id)
        target = self.targets.get(record["host_id"])
        if target is None or target.transport_scope != record["transport_scope"]:
            return self._view(record)
        policy = record["policy_digest"]
        try:
            if record["state"] == "preparing":
                raw = self.invoker(target, "plan_status", policy_digest=policy, plan_id=plan_id)
                record = self._save_plan(record, raw)
            elif record["state"] == "submitting":
                plan = self._saved_plan(record)
                if plan is None:
                    raise ValueError("已批准记录缺少预览。")
                expired = self.clock() >= _utc(plan.expires_at)
                fields = {"action_id": plan.action_id}
                if expired:
                    fields.update(
                        plan_id=plan.plan_id,
                        plan_digest=plan.plan_digest,
                        mode_revision=plan.mode_revision,
                    )
                operation = "reconcile_status" if expired else "status"
                raw = self.invoker(target, operation, policy_digest=policy, **fields)
                record = self._save_receipt(
                    record, plan, raw, source=operation, confirm_not_started=expired
                )
        except (NginxActionTransportError, ValueError, OSError):
            pass
        return self._view(record)

    def observe(self, plan_id):
        with self._database() as db:
            record = self._record(db, plan_id)
        target = self._target(record["host_id"], record)
        plan = self._saved_plan(record)
        if record["state"] != "submitting" or plan is None:
            raise HTTPException(409, "独立复验要求原处置仍待核实。")
        try:
            raw = self.invoker(target, "observe", action_id=plan.action_id)
            observed = _receipt(raw, record, plan)
            if observed.status == "unknown" and observed.reconciliation_status is not None:
                record = self._save_receipt(record, plan, raw, source="observe")
        except (NginxActionTransportError, ValueError, OSError):
            pass
        return self._view(record)


def register_nginx_action_routes(application, service, protected):
    def guarded(call):
        try:
            return call()
        except (sqlite3.Error, ValueError):
            raise HTTPException(503, "Nginx 处置记录暂时无法核实。") from None

    @application.get("/api/nginx-actions", dependencies=protected)
    def listed():
        return guarded(service.list)

    @application.post("/api/nginx-actions/prepare", dependencies=protected)
    def prepare(body: Prepare):
        return guarded(lambda: service.prepare(body))

    @application.get("/api/nginx-actions/{plan_id}", dependencies=protected)
    def status(plan_id: str):
        return guarded(lambda: service.get(plan_id))

    @application.post("/api/nginx-actions/{plan_id}/approve", dependencies=protected)
    def approve(plan_id: str, body: Approve):
        return guarded(lambda: service.approve(plan_id, body))

    @application.post("/api/nginx-actions/{plan_id}/observe", dependencies=protected)
    def observe(plan_id: str):
        return guarded(lambda: service.observe(plan_id))

    @application.post("/api/nginx-actions/{plan_id}/rollback/prepare", dependencies=protected)
    def restore(plan_id: str, body: PrepareRestore):
        return guarded(lambda: service.prepare_restore(plan_id, body))
