"""One durable model attempt gates each automatic native repair candidate."""

import contextlib
import json
import secrets
from datetime import UTC, datetime

from opsark import vulnerability_ai as domain
from opsark import vulnerability_ai_focus as focus
from opsark.ai_dispatch import DispatchRejected, dispatch_guard
from opsark.ai_egress import AIEgressBlocked
from opsark.automatic_store import HEX, ID, candidate_identity, digest, instant
from opsark.baselines import scope_for
from opsark.control_modes import ControlPolicy, automatic_window_open
from opsark.vulnerability_ai_api import AnalysisRequest

_MESSAGES = {
    "analysis_started": "自动分析意图和预算已持久保存；本候选只发送这一个模型请求。",
    "analysis_failed": "模型结果未通过校验；保留原分析，不自动重发，也不转为确定性安装。",
    "no_proposal": "模型没有选择当前候选；保留分析，没有自动修复提交。",
    "analysis_completed": "模型候选与当前证据已核对；仍须核验原生事务和独立执行授权。",
    "blocked": "当前模式、授权、提供方、证据或分析绑定未能核实；没有新自动动作。",
    "egress_blocked": "AI 外发门禁已拦截本次请求，当前候选保留待复核。",
    "analysis_unknown": "原模型请求结果未知或仍待核实；保留原 ID，不重新发送。",
}


def _matches(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _time(value):
    return instant(datetime.fromisoformat(value))


class AutomaticAIGate:
    """Model consent and proposal checks; this object never prepares or submits a patch."""

    def __init__(self, ai_service, store, *, now=None):
        self.ai_service = ai_service
        self.store = store
        self.now = now or (lambda: datetime.now(UTC))
        self.owner = secrets.token_hex(16)
        self.last_error = None
        self.is_stopping = lambda: False

    def _alert(self, candidate, kind, request_key=None):
        self.store.emit_ai_alert(
            candidate["host_id"],
            digest({"automatic_ai": request_key or candidate["id"], "kind": kind}),
            kind,
            _MESSAGES[kind],
            request_key=request_key,
            candidate_id=candidate["id"],
            now=instant(self.now()),
        )

    def _context(self, candidate, scan, policy, mode):
        policy = ControlPolicy.model_validate(policy.model_dump())
        configured = self.ai_service.service.automation
        if configured.policy.model_dump() != policy.model_dump():
            raise ValueError("Automatic policy changed")
        current_mode = configured.status()
        if (
            mode.get("mode") != "automatic"
            or type(mode.get("revision")) is not int
            or mode["revision"] < 0
            or mode.get("mode_sync_complete") is not True
            or any(
                current_mode.get(k) != mode[k] for k in ("mode", "revision", "mode_sync_complete")
            )
        ):
            raise ValueError("Automatic mode is not current")
        grant, consent = policy.automatic, policy.automatic_ai
        host = candidate["host_id"]
        target = self.ai_service.service.target(host)
        public_scope = scope_for(target.host.public)
        automatic_scope = digest(
            {
                "channel": "automatic-patch/v1",
                "host_scope": public_scope,
                "policy_digest": target.policy_digest,
            }
        )
        if (
            not policy.enabled
            or consent is None
            or not consent.enabled
            or grant is None
            or not automatic_window_open(grant, instant(self.now()))
            or host not in policy.host_ids
            or host not in grant.host_ids
            or "os_security_upgrade" not in policy.allowed_actions
            or candidate["package"] not in policy.allowed_packages
            or candidate["package"] not in grant.allowed_packages
            or grant.target_policy_digests.get(host) != target.policy_digest
            or candidate.get("scope_hash") != automatic_scope
            or candidate.get("grant_id") != grant.grant_id
            or candidate.get("grant_digest") != grant.grant_digest
            or not _matches(candidate.get("id"), HEX)
            or candidate["id"]
            != candidate_identity(
                host,
                automatic_scope,
                candidate["finding_id"],
                candidate["current_version"],
                candidate["candidate_version"],
            )
        ):
            raise ValueError("Automatic model consent or Root scope is unavailable")
        preview = self.ai_service.preview(host)
        if (
            preview.get("configured") is not True
            or preview.get("fresh") is not True
            or preview.get("provider_binding") != consent.provider_fingerprint
            or preview.get("host_scope_hash") != public_scope
            or preview.get("host_id") != host
            or preview.get("policy_digest") != target.policy_digest
            or preview.get("scan_id") != scan.get("scan_id")
            or preview.get("state_digest") != scan.get("apt_state_digest")
            or not _matches(preview.get("input_digest"), HEX)
            or scan.get("host_id") != host
            or scan.get("policy_digest") != target.policy_digest
            or scan.get("apt_configuration_safe") is not True
            or not 0 <= (instant(self.now()) - _time(scan["collected_at"])).total_seconds() <= 900
        ):
            raise ValueError("Current provider and scan binding is unavailable")
        choices = [
            c
            for c in preview["catalog"]
            if c.get("eligible") is True
            and all(
                c.get(k) == candidate.get(k)
                for k in ("finding_id", "package", "current_version", "candidate_version")
            )
            and c.get("advisory") in grant.allowed_advisories
            and c.get("risk_level") in grant.allowed_risk_levels
            and c.get("requires_reboot") is False
            and (
                c.get("requires_service_restart") is False
                or c.get("requires_service_restart") is True
                and policy.allow_service_restart
                and grant.allow_service_restart
            )
            and _matches(c.get("candidate_sha256"), HEX)
        ]
        if len(choices) != 1:
            raise ValueError("No unique authorized model candidate")
        key = digest(
            {
                "channel": "automatic-ai/v1",
                "host_scope": public_scope,
                "finding_id": candidate["finding_id"],
                "package": candidate["package"],
                "current_version": candidate["current_version"],
                "candidate_version": candidate["candidate_version"],
                "provider_fingerprint": consent.provider_fingerprint,
            }
        )
        selection = {"kind": "single_candidate", "candidate_id": choices[0]["candidate_id"]}
        old = self.store.get_ai_request(key, now=instant(self.now()))
        if old is not None:
            # The stable billable key deliberately stays v1. Changing the analysis
            # format must not re-arm a failed or unknown historical request.
            original = self.ai_service.store.get(host, old["analysis_id"])
            if original is not None:
                selection = self.ai_service._record_selection(original)
            else:
                archived = self.ai_service.store.get_source(host, old["analysis_id"])
                if archived is None:
                    raise ValueError("Original analysis source is unavailable")
                selection = archived["source"].get("selection")
        else:
            # Retention precedes the budget transaction. A crash in between can
            # leave a v1 source without a billable intent; retain its format too.
            analysis_id = digest({"automatic_ai_analysis": key})[:32]
            archived = self.ai_service.store.get_source(host, analysis_id)
            if archived is not None:
                selection = archived["source"].get("selection")
        if selection is not None:
            expected_selection = {
                "kind": "single_candidate",
                "candidate_id": choices[0]["candidate_id"],
            }
            if not focus.valid_selection(selection) or selection != expected_selection:
                raise ValueError("Original model focus no longer matches the native candidate")
            focused = self.ai_service.preview(host, selection=selection)
            if (
                any(
                    focused.get(name) != preview.get(name)
                    for name in (
                        "host_id",
                        "host_scope_hash",
                        "policy_digest",
                        "scan_id",
                        "state_digest",
                        "provider_binding",
                        "context_scope",
                        "catalog",
                        "source_mode",
                        "source_mode_revision",
                        "mode_revision",
                        "fresh",
                        "configured",
                    )
                )
                or focused.get("selection") != selection
            ):
                raise ValueError("Source changed while selecting the focused model input")
            preview = focused
        return policy, grant, consent, preview, choices[0], public_scope, key

    @staticmethod
    def _bound(request, candidate, grant, preview, key):
        return (
            isinstance(request, dict)
            and request.get("request_key") == key
            and request.get("host_id") == candidate["host_id"]
            and request.get("scope_hash") == candidate["scope_hash"]
            and request.get("candidate_id") == candidate["id"]
            and request.get("grant_id") == grant.grant_id
            and request.get("provider_fingerprint") == preview["provider_binding"]
            and request.get("input_digest") == preview["input_digest"]
            and _matches(request.get("analysis_id"), ID)
        )

    def _proof(self, request, candidate, record, context):
        _policy, grant, _consent, preview, selected, _public_scope, key = context
        if not self._bound(request, candidate, grant, preview, key):
            raise ValueError("Original model request no longer matches")
        if (
            record.get("analysis_id") != request["analysis_id"]
            or record.get("status") != "completed"
            or record.get("applicable") is not True
            or record.get("stale") is not False
            or record.get("input_digest") != request["input_digest"]
            or any(
                record.get(k) != preview.get(k)
                for k in (
                    "host_id",
                    "host_scope_hash",
                    "policy_digest",
                    "scan_id",
                    "state_digest",
                    "provider_binding",
                    "context_scope",
                    "input",
                    "catalog",
                    "selection",
                )
            )
        ):
            raise ValueError("Model analysis is not current")
        result = record["result"]
        if (
            result.get("status") != "completed"
            or result.get("actions_executable") is not False
            or result.get("input_digest") != request["input_digest"]
            or result.get("model") != preview.get("model_name")
            or digest(
                {
                    "analysis_id": request["analysis_id"],
                    "input_digest": request["input_digest"],
                    "result": result,
                }
            )
            != record.get("analysis_digest")
        ):
            raise ValueError("Analysis digest or execution boundary changed")
        payload = {k: result[k] for k in domain.AnalysisPayload.model_fields}
        text = json.dumps(payload, ensure_ascii=True, allow_nan=False)
        if len(text.encode()) > domain.MAX_RESPONSE_BYTES:
            raise ValueError("Saved model payload exceeded its budget")
        engine = focus if "selection" in record else domain
        engine.validate_document(
            {"choices": [{"finish_reason": "stop", "message": {"content": text}}]},
            preview["input"],
            self.ai_service.settings,
        )
        choices = [
            p
            for p in record["proposals"]
            if p.get("candidate_id") == selected["candidate_id"] and p.get("candidate") == selected
        ]
        if len(choices) != 1:
            raise ValueError("Model did not select this native candidate")
        proposal = choices[0]
        expected = digest(
            {"analysis": record["analysis_digest"], "candidate": selected["candidate_id"]}
        )[:32]
        if proposal.get("proposal_id") != expected or not any(
            p.get("candidate_id") == selected["candidate_id"]
            and p.get("evidence_refs") == proposal.get("evidence_refs")
            for p in result["proposals"]
        ):
            raise ValueError("Selected proposal identity changed")
        return {
            "request_key": key,
            "analysis_id": request["analysis_id"],
            "input_digest": request["input_digest"],
            "analysis_digest": record["analysis_digest"],
            "proposal_id": proposal["proposal_id"],
            "candidate_id": selected["candidate_id"],
            "provider_fingerprint": preview["provider_binding"],
        }

    @staticmethod
    def _reference(proof):
        return {k: v for k, v in proof.items() if k != "request_key"}

    def _finish(self, request, status, kind, candidate, *, proof=None):
        self.store.finish_ai_request(
            request["request_key"],
            self.owner,
            status=status,
            result_ref=self._reference(proof) if proof is not None else None,
            detail=_MESSAGES[kind],
            now=instant(self.now()),
        )
        self._alert(candidate, kind, request["request_key"])

    @staticmethod
    def _dispatch_binding(context):
        policy, _grant, _consent, preview, selected, public_scope, key = context
        return digest(
            {
                "policy": policy.model_dump(mode="json"),
                "preview": {
                    name: value
                    for name, value in preview.items()
                    if name != "eligibility_evaluated_at"
                },
                "selected": selected,
                "host_scope": public_scope,
                "request_key": key,
            }
        )

    def _require_dispatch(self, candidate, scan, policy, mode, request, binding):
        lock = self.ai_service.service.admission_lock
        if not lock.acquire(blocking=False):
            raise DispatchRejected()
        try:
            if self.is_stopping():
                raise DispatchRejected()
            context = self._context(candidate, scan, policy, mode)
            _policy, grant, _consent, preview, _selected, _scope, key = context
            current = self.store.get_ai_request(key, now=instant(self.now()))
            if (
                self._dispatch_binding(context) != binding
                or not self._bound(current, candidate, grant, preview, key)
                or current.get("owner") != self.owner
                or current.get("status") != "submission_intent"
                or current.get("analysis_id") != request["analysis_id"]
                or current.get("deadline_at") != request["deadline_at"]
                or instant(self.now()) >= _time(request["deadline_at"])
                or not automatic_window_open(grant, instant(self.now()))
                or self.is_stopping()
            ):
                raise DispatchRejected()
        except Exception:
            raise DispatchRejected() from None
        finally:
            lock.release()

    def require_proposal(self, candidate, scan, policy, mode):
        request = None
        try:
            if self.is_stopping():
                raise ValueError("Automatic model processing is stopping")
            context = self._context(candidate, scan, policy, mode)
            _policy, grant, consent, preview, _selected, _public_scope, key = context
            old = self.store.get_ai_request(key, now=instant(self.now()))
            if old is not None:
                record = self.ai_service.get(candidate["host_id"], old["analysis_id"])
                if old.get("status") != "completed":
                    self._alert(
                        candidate,
                        "analysis_unknown"
                        if old.get("status") in {"unknown", "submission_intent"}
                        else "analysis_failed",
                        key,
                    )
                    return None
                proof = self._proof(old, candidate, record, context)
                if old.get("result_ref") != self._reference(proof):
                    raise ValueError("Saved model admission changed")
                self._alert(candidate, "analysis_completed", key)
                self.last_error = None
                return proof
            analysis_id = digest({"automatic_ai_analysis": key})[:32]
            dispatch_binding = self._dispatch_binding(context)
            request_body = AnalysisRequest(
                host_id=candidate["host_id"],
                analysis_id=analysis_id,
                expected_input_digest=preview["input_digest"],
                confirm_send=True,
                selection=preview.get("selection"),
            )
            archived = self.ai_service.prepare_source(request_body)
            if archived.get("status") != "retained":
                raise ValueError("Original model evidence was not retained")
            # The archive is durable before the independent model-budget intent.
            self._context(candidate, scan, policy, mode)
            if self.is_stopping():
                raise ValueError("Automatic processing stopped after source retention")
            request = self.store.begin_ai_request(
                request_key=key,
                host_id=candidate["host_id"],
                scope_hash=candidate["scope_hash"],
                candidate_id=candidate["id"],
                grant_id=grant.grant_id,
                provider_fingerprint=consent.provider_fingerprint,
                analysis_id=analysis_id,
                input_digest=preview["input_digest"],
                owner=self.owner,
                daily_limit=consent.max_analyses_per_day,
                total_limit=consent.max_total_analyses,
                now=instant(self.now()),
            )
            if request is None or request.get("dispatch") is not True:
                self._alert(candidate, "blocked", key)
                return None
            self._require_dispatch(candidate, scan, policy, mode, request, dispatch_binding)
            self._alert(candidate, "analysis_started", key)
            if self.is_stopping():
                raise ValueError("Automatic processing stopped before model dispatch")

            def current_dispatch():
                self._require_dispatch(candidate, scan, policy, mode, request, dispatch_binding)

            with dispatch_guard(current_dispatch) as admission:
                try:
                    record = self.ai_service.analyze(
                        AnalysisRequest(
                            host_id=candidate["host_id"],
                            analysis_id=request["analysis_id"],
                            expected_input_digest=request["input_digest"],
                            confirm_send=True,
                            selection=preview.get("selection"),
                        )
                    )
                except AIEgressBlocked:
                    self._finish(request, "failed", "egress_blocked", candidate)
                    return None
                except Exception:
                    if admission.rejected:
                        raise DispatchRejected() from None
                    self._finish(request, "unknown", "analysis_unknown", candidate)
                    return None
            if admission.rejected:
                raise DispatchRejected()
            status = record.get("status")
            if (
                status != "completed"
                or record.get("stale") is not False
                or record.get("applicable") is not True
            ):
                state = status if status in {"failed", "unknown", "refused", "stale"} else "failed"
                egress_blocked = (record.get("result") or {}).get(
                    "failure_kind"
                ) == "ai_egress_blocked"
                self._finish(
                    request,
                    state,
                    "egress_blocked"
                    if egress_blocked
                    else ("analysis_unknown" if state == "unknown" else "analysis_failed"),
                    candidate,
                )
                return None
            if not record.get("proposals"):
                self._finish(request, "failed", "no_proposal", candidate)
                return None
            if instant(self.now()) >= _time(request["deadline_at"]):
                self._finish(request, "unknown", "analysis_unknown", candidate)
                return None
            current = self._context(candidate, scan, policy, mode)
            proof = self._proof(request, candidate, record, current)
            self._finish(request, "completed", "analysis_completed", candidate, proof=proof)
            if not self.validate_proof(candidate, scan, policy, mode, proof):
                raise ValueError("Model admission changed before native planning")
            self.last_error = None
            return proof
        except AIEgressBlocked:
            self.last_error = _MESSAGES["egress_blocked"]
            with contextlib.suppress(Exception):
                self._alert(
                    candidate, "egress_blocked", request.get("request_key") if request else None
                )
            return None
        except Exception:
            self.last_error = _MESSAGES["blocked"]
            if request is not None and request.get("dispatch") is True:
                with contextlib.suppress(Exception):
                    self._finish(request, "stale", "blocked", candidate)
            with contextlib.suppress(Exception):
                self._alert(candidate, "blocked", request.get("request_key") if request else None)
            return None

    def validate_proof(self, candidate, scan, policy, mode, proof):
        try:
            context = self._context(candidate, scan, policy, mode)
            key = context[-1]
            request = self.store.get_ai_request(key, now=instant(self.now()))
            if request is None or request.get("status") != "completed":
                return False
            record = self.ai_service.get(candidate["host_id"], request["analysis_id"])
            expected = self._proof(request, candidate, record, context)
            return proof == expected and request.get("result_ref") == self._reference(expected)
        except Exception:
            return False

    def status(self):
        try:
            policy = ControlPolicy.model_validate(
                self.ai_service.service.automation.policy.model_dump()
            )
            consent, grant = policy.automatic_ai, policy.automatic
            fields = (
                "request_key",
                "host_id",
                "candidate_id",
                "analysis_id",
                "status",
                "created_at",
                "updated_at",
                "deadline_at",
            )
            requests = [
                {k: r[k] for k in fields if k in r} for r in self.store.ai_requests(limit=100)
            ]
            quotas = (
                {
                    host: self.store.ai_quotas(host, grant.grant_id, now=instant(self.now()))
                    for host in grant.host_ids
                }
                if grant is not None
                else {}
            )
            return {
                "enabled": bool(consent and consent.enabled),
                "policy": consent.model_dump(mode="json") if consent else None,
                "provider_fingerprint": consent.provider_fingerprint if consent else None,
                "requests": requests,
                "alerts": self.store.ai_alerts(limit=100),
                "quotas": quotas,
                "last_error": self.last_error,
            }
        except Exception:
            return {
                "enabled": False,
                "policy": None,
                "requests": [],
                "alerts": [],
                "quotas": None,
                "last_error": _MESSAGES["blocked"],
            }
