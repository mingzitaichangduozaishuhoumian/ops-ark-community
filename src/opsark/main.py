"""Authenticated investigation and approved repair APIs with a same-origin console."""

import hashlib
import hmac
import json
import re
import sqlite3
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from opsark import __version__
from opsark.access_recheck_api import access_profile, register_access_recheck_routes
from opsark.action_handoff_api import register_action_handoff_routes
from opsark.action_handoff_projection import ActionHandoffProjection
from opsark.action_handoff_recheck_store import ActionHandoffRecheckStore
from opsark.activation_api import ActivationService, register_activation_routes
from opsark.activation_monitor import ActivationMonitor
from opsark.activation_recovery_api import (
    ActivationRecoveryService,
    register_activation_recovery_routes,
)
from opsark.activation_recovery_store import ActivationRecoveryStore
from opsark.activation_store import ActivationStore
from opsark.ai import explain
from opsark.ai_egress import AIEgressBlocked, guard_source
from opsark.ai_provider import provider_status, resolve_ai_settings
from opsark.automatic_ai import AutomaticAIGate
from opsark.automatic_monitor import AutomaticMonitor
from opsark.automatic_store import AutomaticStore
from opsark.automation_store import AutomationStore, ModeChange, StaleModeError, load_policy
from opsark.baselines import BaselineStore, compare, matches_host_scope, snapshot
from opsark.baselines import diagnostic_scope_for as scope_for
from opsark.business_readiness import (
    BusinessReadiness,
    business_profile_digest,
    run_access_readiness,
    run_business_readiness,
)
from opsark.change_record_api import register_change_record_routes
from opsark.collector import collect_ssh
from opsark.compose_discovery import (
    ComposeDiscovery,
    ComposeRegistrationPreview,
    ComposeSelection,
    DiscoveryRefused,
    preview_compose_registration,
    run_compose_discovery,
)
from opsark.compose_generation import GenerationComparison, collect_generation, stable_observation
from opsark.compose_generation import binding_digest as compose_generation_binding_digest
from opsark.compose_generation_store import ComposeGenerationStore
from opsark.compose_volume_metadata import (
    ComposeVolumeObservation,
    run_compose_volume_metadata,
)
from opsark.compose_volume_metadata import binding_digest as compose_volume_binding_digest
from opsark.config import HostConfig, Settings, load_hosts, load_patch_targets, load_settings
from opsark.container_report_recheck_api import (
    container_recheck_profile,
    register_container_report_recheck_routes,
)
from opsark.container_restart_client import load_container_restart_targets
from opsark.container_restarts import ContainerRestartService, register_container_restart_routes
from opsark.defense_ai import DefenseAIService
from opsark.defense_ai_api import register_defense_ai_routes
from opsark.defense_api import DefenseService, defense_service_scope, register_defense_routes
from opsark.defense_config import load_defense_targets
from opsark.defense_policy import load_policy as load_defense_policy
from opsark.defense_recheck import DefenseRecheckService
from opsark.defense_recheck_api import register_defense_recheck_routes
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_session import DefenseSessionCoordinator
from opsark.defense_session_api import register_defense_session_routes
from opsark.defense_session_worker import DefenseSessionWorker
from opsark.defense_store import DefenseStore
from opsark.defense_task_watch import DefenseTaskWatcher
from opsark.defense_task_watch_api import register_defense_task_watch_routes
from opsark.defense_task_watch_store import DefenseTaskWatchStore
from opsark.diagnostics import diagnose
from opsark.disk_reclaim import allocation_label, allocation_number, validate_disk_comparison
from opsark.handoff_timeline import (
    BusinessHandoffRecheck,
    HandoffRecheckRequest,
    HandoffRecheckRow,
    HandoffRechecks,
    HandoffTimeline,
    build_handoff_timeline,
    handoff_approval_digest,
    report_matches_handoff_scope,
)
from opsark.health import evaluate_health
from opsark.host_onboarding import (
    HostOnboarding,
    HostOnboardingError,
    HostOnboardingRequest,
    prepare_host_onboarding,
)
from opsark.host_preflight import HostPreflight, run_host_preflight
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope
from opsark.models import (
    AIExplanation,
    BaselineInfo,
    BaselineRequest,
    ExplainRequest,
    HostPreflightRequest,
    InvestigationRequest,
    Report,
)
from opsark.nginx_action_client import load_nginx_targets
from opsark.nginx_actions import NginxActionService, register_nginx_action_routes
from opsark.nginx_dependencies import (
    NginxDependencies,
    NginxPathObservation,
    dependency_binding_digest,
    path_observation_binding_digest,
    run_container_restart_impact,
    run_nginx_dependencies,
)
from opsark.nginx_error_window import metadata_line
from opsark.patch_api import (
    ModeSynchronizationError,
    PatchService,
    register_patch_routes,
    targets_scope,
)
from opsark.patch_monitor import PatchMonitor
from opsark.patch_store import ACTIVE_STATES, TERMINAL_STATES, PatchStore
from opsark.platforms import capabilities as platform_capabilities
from opsark.recovery_api import RecoveryService, register_recovery_routes
from opsark.redaction import sanitize_collection
from opsark.replay import collect_replay, list_samples
from opsark.report_handoff import handoff_markdown
from opsark.security_ai import analysis_input, analyze_alert, guard_alert_source, input_digest
from opsark.security_ai_store import SecurityAIStore
from opsark.security_models import AcknowledgeAlert, SecurityAnalysisRequest
from opsark.security_monitor import SecurityMonitor
from opsark.security_store import SecurityStore
from opsark.ssh_defense_status import (
    DefenseAction,
    DefenseActions,
    DefenseQuery,
    DefenseStatusStore,
    run_defense_status,
)
from opsark.storage import ReportStore
from opsark.vulnerability_ai_api import VulnerabilityAIService, register_vulnerability_ai_routes
from opsark.vulnerability_ai_store import VulnerabilityAIStore
from opsark.vulnerability_monitor import VulnerabilityMonitor
from opsark.vulnerability_store import VulnerabilityStore
from opsark.vulnerability_webhook import load_vulnerability_webhook
from opsark.vulnerability_webhook_worker import VulnerabilityWebhookWorker
from opsark.web_security_store import WebSecurityStore

_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}


class _BodyLimitMiddleware:
    """Bound JSON bodies even when Content-Length is absent or misleading."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] in _READ_METHODS
            or not scope["path"].startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None:
            try:
                declared = int(length)
            except ValueError:
                declared = -1
            if declared < 0:
                await JSONResponse({"detail": "无效的请求长度。"}, status_code=400)(
                    scope, receive, send
                )
                return
            if declared > 16_384:
                await JSONResponse({"detail": "请求正文超出大小限制。"}, status_code=413)(
                    scope, receive, send
                )
                return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > 16_384:
                await JSONResponse({"detail": "请求正文超出大小限制。"}, status_code=413)(
                    scope, receive, send
                )
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


def _same_origin(origin: str, request: Request) -> bool:
    try:
        given = urlsplit(origin)
        current = urlsplit(str(request.base_url))
        if given.scheme not in {"http", "https"} or given.username or given.password:
            return False
        if given.path not in {"", "/"} or given.query or given.fragment:
            return False
        return (
            given.scheme,
            given.hostname,
            given.port or (443 if given.scheme == "https" else 80),
        ) == (
            current.scheme,
            current.hostname,
            current.port or (443 if current.scheme == "https" else 80),
        )
    except ValueError:
        return False


def _inline(value: object) -> str:
    value = escape(str(value).replace("\r", " ").replace("\n", "\\n"), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", value)


def _code_block(value: str) -> str:
    lengths = [len(match.group()) for match in re.finditer(r"`+", value)]
    fence = "`" * max(3, max(lengths, default=0) + 1)
    return f"{fence}text\n{value}\n{fence}"


def report_markdown(report: Report) -> str:
    validate_disk_comparison(report)
    source = (
        "回放样本：证据为预置虚构数据，不是服务器实测结果。"
        if report.source == "replay"
        else "SSH 只读采集：仅代表此次已完成检查，不代表故障已经修复。"
    )
    lines = [
        f"# {_inline(report.title)}",
        "",
        source,
        "",
        f"报告：{_inline(report.id)}",
        f"主机：{_inline(report.host_name)}",
        f"场景：{_inline(report.scenario)}",
        f"时间：{report.created_at.isoformat()}",
        f"状态：{_inline(report.status)}",
        "",
        "## 调查摘要",
        "",
        _inline(report.summary),
    ]
    compatibility = report.compatibility
    lines.extend(
        [
            "",
            "## 目标环境适配",
            "",
            f"状态：{compatibility.status}；系统：{_inline(compatibility.os_id or '未知')}；"
            f"版本：{_inline(compatibility.version_id or '未知')}；"
            f"架构：{_inline(compatibility.architecture or '未知')}",
            _inline(compatibility.detail),
            "缺失工具："
            + _inline(", ".join(compatibility.missing_tools) or "未记录；需结合探针状态"),
            "证据：" + _inline(", ".join(compatibility.evidence_ids) or "无"),
        ]
    )
    for label, findings in (("已知事实", report.facts), ("候选原因", report.candidates)):
        lines.extend(["", f"## {label}", ""])
        for finding in findings:
            refs = ", ".join(_inline(ref) for ref in finding.evidence_ids)
            lines.append(f"- {_inline(finding.text)}（证据：{refs or '无'}）")
        if not findings:
            lines.append("没有足够证据形成该项结论。")
    for label, entries in (("缺失证据", report.missing), ("下一步", report.next_steps)):
        lines.extend(["", f"## {label}", ""])
        lines.extend(f"- {_inline(entry)}" for entry in entries)
        if not entries:
            lines.append("本报告没有额外记录；不代表检查已覆盖全部环境。")
    lines.extend(["", "## 执行与恢复验收", "", _inline(report.action.reason)])
    lines.append("本调查没有执行修复或封禁；补丁任务另有记录，调查结果不构成恢复验收。")
    for item in report.verification:
        lines.append(f"- {_inline(item.name)}：{item.status}；{_inline(item.detail)}")
        if item.evidence_ids:
            lines.append("  证据：" + ", ".join(_inline(ref) for ref in item.evidence_ids))
    comparison = report.comparison
    lines.extend(["", "## 观测基线与差异", "", f"对照状态：{comparison.status}"])
    lines.append("观测基线不证明健康，不是已加载配置或可恢复的配置备份。")
    if comparison.baseline_report_id:
        lines.append("基线报告：" + _inline(comparison.baseline_report_id))
    for item in comparison.changes:
        label = allocation_label(item.field)
        lines.append(
            f"- {_inline(label or item.field)}：{_inline(item.before)} → {_inline(item.after)}"
        )
        if label is not None:
            delta = allocation_number(item.after) - allocation_number(item.before)
            lines.append(f"  已分配字节变化 {delta:+d}；仅聚合观察，不证明单文件原因或可清理量。")
        lines.append("  当前证据：" + ", ".join(_inline(ref) for ref in item.evidence_ids))
    lines.extend("- " + _inline(gap) for gap in comparison.missing)
    lines.extend(["", "## 证据记录", ""])
    for item in report.evidence:
        output = item.output
        if item.check_id == "nginx_errors" and report.nginx_error_window is not None:
            output = metadata_line(report.nginx_error_window)
        lines.extend(
            [
                f"### {_inline(item.id)}",
                "",
                f"检查：{_inline(item.check_id)}；目标：{_inline(item.target)}；来源：{item.source}",
                f"读取或采集时间：{item.collected_at.isoformat()}；状态：{item.status}；截断：{item.truncated}",
                "",
                _code_block(output),
                "",
            ]
        )
    if report.ai.status != "not_requested":
        lines.extend(
            [
                "## AI 补充解释",
                "",
                f"状态：{report.ai.status}",
                "AI 解释不覆盖采集事实，不产生执行权限或恢复结论。",
                "",
                _inline(report.ai.text),
                "",
                "引用：" + ", ".join(_inline(ref) for ref in report.ai.evidence_ids),
            ]
        )
    return "\n".join(lines) + "\n"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    if len(settings.token) < 32:
        raise ValueError("A console token of at least 32 characters is required.")
    if settings.defense_worker_enabled:
        raise ValueError("持续防护执行器尚未完成装配验收，当前只开放显式受控请求。")
    hosts = load_hosts(settings)
    store = ReportStore(settings.data_dir / "reports.sqlite3")
    baseline_store = BaselineStore(settings.data_dir / "baselines.sqlite3")
    generation_store = ComposeGenerationStore(store)
    investigation_lock = Lock()
    ai_lock = Lock()
    web_dir = Path(__file__).resolve().parents[2] / "web"
    security_store = SecurityStore(settings.data_dir / "security.sqlite3")
    defense_status_store = (
        DefenseStatusStore(settings.data_dir / "security.sqlite3")
        if any(host.ssh_defense_action_ids for host in hosts.values())
        else None
    )
    web_security_store = WebSecurityStore(settings.data_dir / "web-security.sqlite3")
    security_ai_store = SecurityAIStore(settings.data_dir / "security-ai.sqlite3")
    patch_targets = load_patch_targets(settings, hosts)
    defense_targets = load_defense_targets(settings, hosts, patch_targets)
    nginx_action_targets = load_nginx_targets(
        settings.nginx_action_inventory_path,
        hosts,
        (*patch_targets.values(), *defense_targets.values()),
    )
    container_restart_targets = load_container_restart_targets(
        settings.container_restart_inventory_path,
        hosts,
        (*patch_targets.values(), *defense_targets.values(), *nginx_action_targets.values()),
    )
    defense_policy = load_defense_policy(settings.defense_policy_path)
    defense_scope = defense_service_scope(defense_targets, defense_policy)
    # This callback is a closed placeholder for computing the immutable registration scope.
    # Only the service's verified participant is installed in the actual coordinator.
    defense_registration = (
        (ModeParticipant("ssh-defense", defense_scope, lambda _snapshot: False),)
        if defense_scope is not None
        else ()
    )
    automation_store = AutomationStore(
        settings.data_dir / "automation.sqlite3",
        load_policy(settings.automation_policy_path),
        driver_scope=targets_scope(patch_targets),
        supplemental_scope=supplemental_scope(defense_registration),
    )
    patch_store = PatchStore(settings.data_dir / "patches.sqlite3")
    patch_service = PatchService(patch_targets, patch_store, automation_store)
    nginx_action_service = NginxActionService(
        nginx_action_targets, automation_store, resolve_report=store.get
    )
    container_restart_service = ContainerRestartService(
        container_restart_targets, automation_store, resolve_report=store.get
    )
    defense_store = DefenseStore(settings.data_dir / "security.sqlite3")
    defense_recheck_store = DefenseRecheckStore(defense_store)
    defense_mode_lock = Lock()
    defense_service = DefenseService(
        settings,
        defense_targets,
        defense_store,
        automation_store,
        policy=defense_policy,
        mode_lock=defense_mode_lock,
        business_profile_store=defense_recheck_store,
    )
    defense_recheck_service = DefenseRecheckService(
        defense_service, hosts, defense_recheck_store, collector=run_business_readiness
    )
    defense_ai_service = DefenseAIService(
        defense_store,
        lambda: settings,
        current_snapshot=defense_service.ai_snapshot,
        validate_admission=defense_service.validate_ai_admission,
        now=defense_service.clock,
    )
    defense_service.ai_service = defense_ai_service
    if any(host_id not in defense_targets for host_id in settings.defense_task_watch_host_ids):
        raise ValueError("原任务只读跟进目标必须具有明确的独立防护登记。")
    defense_task_watch_store = DefenseTaskWatchStore(defense_store)
    defense_task_watcher = DefenseTaskWatcher(
        defense_service,
        defense_task_watch_store,
        settings.defense_task_watch_host_ids,
        settings.defense_task_watch_interval_seconds,
        enabled=settings.defense_task_watch_enabled,
    )
    mode_coordinator = None
    participant = defense_service.participant()
    if participant is not None:
        participants = [participant]
        apt_scope = targets_scope(patch_targets)
        if apt_scope is not None:

            def synchronize_apt(snapshot):
                patch_service.synchronize_mode_targets(
                    {"mode": snapshot.mode, "revision": snapshot.revision}
                )
                return True

            participants.insert(0, ModeParticipant("ubuntu-apt", apt_scope, synchronize_apt))
        mode_coordinator = ModeCoordinator(automation_store, defense_mode_lock, tuple(participants))
        patch_service.mode_coordinator = mode_coordinator
        defense_service.coordinator = mode_coordinator
    if settings.defense_session_enabled and not defense_targets:
        raise ValueError("单次会话必须具有明确的独立防护登记。")
    defense_session_coordinator = DefenseSessionCoordinator(
        defense_service, ai_service=defense_ai_service, clock=defense_service.clock
    )
    defense_session_worker = DefenseSessionWorker(
        defense_session_coordinator, enabled=settings.defense_session_enabled
    )
    vulnerability_ai_store = VulnerabilityAIStore(settings.data_dir / "vulnerability-ai.sqlite3")
    vulnerability_ai_service = VulnerabilityAIService(
        settings, patch_service, vulnerability_ai_store, ai_lock
    )
    automatic_store = AutomaticStore(settings.data_dir / "automatic.sqlite3")
    patch_service.automatic_store = automatic_store
    recovery_service = RecoveryService(patch_service)
    automatic_ai_gate = AutomaticAIGate(vulnerability_ai_service, automatic_store)
    patch_service.automatic_ai_gate = automatic_ai_gate
    automatic_monitor = AutomaticMonitor(patch_service, automatic_store, ai_gate=automatic_ai_gate)
    patch_monitor = PatchMonitor(patch_service)
    vulnerability_webhook = (
        load_vulnerability_webhook(
            settings.vulnerability_webhook_url, settings.vulnerability_webhook_key_file
        )
        if settings.vulnerability_webhook_url is not None
        and settings.vulnerability_webhook_key_file is not None
        else None
    )
    vulnerability_store = VulnerabilityStore(
        settings.data_dir / "vulnerability-watch.sqlite3",
        webhook_destination=vulnerability_webhook.fingerprint if vulnerability_webhook else None,
    )
    vulnerability_ai_service.evidence_observation_store = vulnerability_store
    vulnerability_monitor = VulnerabilityMonitor(settings, patch_service, vulnerability_store)
    vulnerability_webhook_worker = VulnerabilityWebhookWorker(
        vulnerability_store, vulnerability_webhook
    )
    automatic_monitor.vulnerability_monitor = vulnerability_monitor
    activation_store = ActivationStore(settings.data_dir / "patches.sqlite3")
    activation_service = ActivationService(patch_service, activation_store)
    activation_service.evidence_observation_store = vulnerability_store
    activation_recovery_store = ActivationRecoveryStore(
        settings.data_dir / "automatic.sqlite3", automatic=automatic_store
    )
    activation_recovery_service = ActivationRecoveryService(
        patch_service, activation_service, store=activation_recovery_store
    )

    def activation_verified(record):
        original_job_id = record.get("original_job_id", record["job_id"])
        queued = vulnerability_monitor.request_activation_rescan(
            record["host_id"],
            record["activation_id"],
            original_job_id,
            expected_scope=record["scope_hash"],
        )
        if queued is None:
            return None
        return {
            "host_id": record["host_id"],
            "activation_id": record["activation_id"],
            "original_job_id": original_job_id,
            "rescan_request_id": queued["rescan_request_id"],
            "scope_hash": queued["scope_hash"],
            "event_key": queued["event_key"],
        }

    activation_monitor = ActivationMonitor(activation_service, on_verified=activation_verified)
    security_monitor = SecurityMonitor(
        settings, hosts, security_store, investigation_lock, web_store=web_security_store
    )

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        security_monitor.start()
        patch_monitor.start()
        vulnerability_monitor.start()
        vulnerability_webhook_worker.start()
        automatic_monitor.start()
        activation_monitor.start()
        try:
            if settings.defense_task_watch_enabled:
                defense_task_watcher.start()
            if settings.defense_session_enabled:
                defense_session_worker.start()
            yield
        finally:
            defense_service.stopped.set()
            defense_session_worker.stop()
            defense_task_watcher.stop()
            activation_monitor.stop()
            automatic_monitor.stop()
            vulnerability_monitor.stop()
            vulnerability_webhook_worker.stop()
            patch_monitor.stop()
            security_monitor.stop()

    application = FastAPI(
        title="OpsArk investigation and controlled response API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.store = store
    application.state.baselines = baseline_store
    application.state.settings = settings
    application.state.investigation_lock = investigation_lock
    application.state.ai_lock = ai_lock
    application.state.security_store = security_store
    application.state.security_monitor = security_monitor
    application.state.web_security_store = web_security_store
    application.state.security_ai_store = security_ai_store
    application.state.automation_store = automation_store
    application.state.mode_coordinator = mode_coordinator
    application.state.nginx_action_service = nginx_action_service
    application.state.container_restart_service = container_restart_service
    application.state.defense_store = defense_store
    application.state.defense_recheck_store = defense_recheck_store
    application.state.defense_recheck_service = defense_recheck_service
    application.state.defense_service = defense_service
    application.state.defense_ai_service = defense_ai_service
    application.state.defense_task_watch_store = defense_task_watch_store
    application.state.defense_task_watcher = defense_task_watcher
    application.state.defense_session_coordinator = defense_session_coordinator
    application.state.defense_session_worker = defense_session_worker
    application.state.defense_session_store = defense_session_coordinator.store
    application.state.patch_store = patch_store
    application.state.patch_service = patch_service
    application.state.vulnerability_ai_store = vulnerability_ai_store
    application.state.vulnerability_ai_service = vulnerability_ai_service
    application.state.patch_monitor = patch_monitor
    application.state.vulnerability_store = vulnerability_store
    application.state.vulnerability_monitor = vulnerability_monitor
    application.state.automatic_store = automatic_store
    application.state.recovery_service = recovery_service
    application.state.automatic_monitor = automatic_monitor
    application.state.automatic_ai_gate = automatic_ai_gate
    application.state.activation_store = activation_store
    application.state.activation_service = activation_service
    application.state.activation_monitor = activation_monitor
    application.state.activation_recovery_store = activation_recovery_store
    application.state.activation_recovery_service = activation_recovery_service
    application.add_middleware(_BodyLimitMiddleware)
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"],
    )

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
        # Pydantic's default input/ctx fields can reflect secrets submitted by mistake.
        return JSONResponse(
            {"detail": "请求参数不符合接口约定，请检查场景、来源和必填字段。"}, status_code=422
        )

    @application.middleware("http")
    async def boundaries(request: Request, call_next: Callable) -> Response:
        if request.url.path.startswith("/api/"):
            if {key.lower() for key in request.query_params} & {"token", "access_token"}:
                return JSONResponse(
                    {"detail": "控制台令牌只能通过 Authorization 请求头提供。"}, status_code=400
                )
            if request.method not in _READ_METHODS:
                origin = request.headers.get("origin")
                if origin is not None and not _same_origin(origin, request):
                    return JSONResponse({"detail": "拒绝来自其他来源的修改请求。"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def authorize(request: Request) -> None:
        scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied.encode("utf-8"), settings.token.encode("utf-8")
        ):
            raise HTTPException(
                status_code=401,
                detail="需要有效的控制台令牌。",
                headers={"WWW-Authenticate": "Bearer"},
            )

    protected = [Depends(authorize)]

    def find_report(report_id: str) -> Report:
        try:
            report = store.get(report_id)
        except (sqlite3.Error, ValueError) as error:
            raise HTTPException(status_code=503, detail="报告存储暂时不可用。") from error
        if report is None:
            raise HTTPException(status_code=404, detail="报告不存在。")
        return report

    @application.get("/api/status")
    def status() -> dict[str, object]:
        return {"version": __version__, "requires_auth": True}

    @application.get("/api/capabilities", dependencies=protected)
    def capabilities() -> dict[str, object]:
        provider = provider_status(settings)
        return {
            "mode": "read_only",
            "compose_generation": True,
            "change_records": True,
            "container_report_rechecks": True,
            "model_configured": provider["configured"],
            "model_name": provider["model_name"] if provider["configured"] else None,
            "ssh_hosts": len(hosts),
            "host_onboarding": True,
            "host_preflight": True,
            "host_compose_discovery": True,
            "host_nginx_dependencies": True,
            **({"nginx_managed_actions": True} if nginx_action_targets else {}),
            **({"container_restart": True} if container_restart_targets else {}),
            "business_readiness": True,
            "access_rechecks": True,
            "ssh_defense_status": defense_status_store is not None,
            "ssh_defense_transactions": bool(defense_targets),
            "ssh_defense_history": True,
            "ssh_defense_rechecks": True,
            "ssh_defense_execution": bool(defense_targets and defense_policy.enabled),
            "ssh_defense_continuous_execution": False,
            "ssh_defense_task_watch": True,
            "ssh_defense_sessions": True,
            "ssh_defense_ai": bool(defense_targets and defense_policy.ai.enabled),
            "handoff_timeline": True,
            "handoff_recheck": True,
            "action_handoff": True,
            "site_checks": True,
            "baselines": True,
            "platforms": platform_capabilities(),
            "security_observation": True,
            "security_web": True,
            "security_ai": True,
            "automation_modes": True,
            "vulnerability_remediation": True,
            "vulnerability_watch": True,
            "automatic_repair": True,
            "automatic_recovery": True,
            "vulnerability_ai": True,
            "vulnerability_ai_focus": True,
            "service_activation": True,
            "activation_recovery": True,
            "automatic_ai": True,
            "vulnerability_evidence": True,
        }

    @application.get("/api/automation", dependencies=protected)
    def automation_status() -> dict:
        try:
            return (
                mode_coordinator.status()
                if mode_coordinator is not None
                else automation_store.status()
            )
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="自动化模式状态暂时不可用。") from None

    @application.put("/api/automation", dependencies=protected)
    def automation_mode(body: ModeChange) -> dict:
        try:
            return patch_service.change_mode(body)
        except StaleModeError:
            raise HTTPException(status_code=409, detail="模式或策略已变化，请重新加载。") from None
        except ModeSynchronizationError:
            raise HTTPException(
                status_code=503, detail="模式已保存但未同步全部服务器，新修复提交已停止。"
            ) from None
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="模式未保存，请检查控制端状态。") from None

    register_patch_routes(application, patch_service, protected)
    register_defense_routes(application, defense_service, protected)
    register_defense_ai_routes(application, defense_ai_service, protected)
    register_defense_recheck_routes(application, defense_recheck_service, protected)
    register_defense_task_watch_routes(
        application, defense_task_watcher, defense_task_watch_store, protected
    )
    register_defense_session_routes(
        application, defense_session_coordinator, defense_session_worker, protected
    )
    register_recovery_routes(application, recovery_service, protected)
    register_vulnerability_ai_routes(application, vulnerability_ai_service, protected)
    register_activation_routes(application, activation_service, protected)
    register_activation_recovery_routes(application, activation_recovery_service, protected)
    register_nginx_action_routes(application, nginx_action_service, protected)

    def collect_restart_impact(registered: HostConfig, container_id: str):
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(409, "已有只读检查正在运行，请稍后重试。")
        try:
            if load_hosts(settings).get(registered.public.id) != registered:
                raise HTTPException(409, "当前主机登记已变更，请重新加载登记。")
            result = run_container_restart_impact(registered, settings, container_id)
            if load_hosts(settings).get(registered.public.id) != registered:
                raise HTTPException(409, "当前主机登记已变更，请重新加载登记。")
            return result
        finally:
            investigation_lock.release()

    register_container_restart_routes(
        application, container_restart_service, protected, collect_impact=collect_restart_impact
    )
    register_access_recheck_routes(
        application.router,
        store,
        protected,
        find_report=find_report,
        registered_hosts=hosts,
        current_hosts=lambda: load_hosts(settings),
        collect=lambda host: run_access_readiness(host),
        collection_lock=investigation_lock,
    )
    register_change_record_routes(
        application.router,
        store,
        protected,
        find_report=find_report,
        current_hosts=lambda: load_hosts(settings),
        baselines=baseline_store,
        generations=generation_store,
    )
    register_container_report_recheck_routes(
        application.router,
        store,
        protected,
        find_report=find_report,
        registered_hosts=hosts,
        current_hosts=lambda: load_hosts(settings),
        collect=lambda host: run_access_readiness(host),
        collection_lock=investigation_lock,
    )
    action_rechecks = ActionHandoffRecheckStore(store)
    register_action_handoff_routes(
        application.router,
        ActionHandoffProjection(
            store, nginx_action_service, container_restart_service, action_rechecks
        ),
        action_rechecks,
        protected,
        nginx=nginx_action_service,
        container=container_restart_service,
        find_report=find_report,
        registered_hosts=hosts,
        current_hosts=lambda: load_hosts(settings),
        collect=lambda host: run_business_readiness(host),
        collection_lock=investigation_lock,
    )

    @application.get("/api/ai/status", dependencies=protected)
    def ai_status() -> dict:
        return provider_status(settings)

    @application.get("/api/automatic/status", dependencies=protected)
    def automatic_status() -> dict:
        try:
            return {**automatic_monitor.status(), "recoveries": automatic_store.list_recoveries()}
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(
                status_code=503, detail="自动修复授权或安全状态暂时不可用。"
            ) from None

    @application.get("/api/automatic/ai/alerts", dependencies=protected)
    def automatic_ai_alerts() -> list[dict]:
        try:
            return automatic_store.ai_alerts()
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(503, "自动 AI 告警暂时不可用。") from None

    @application.post("/api/automatic/ai/alerts/{alert_id}/ack", dependencies=protected)
    def acknowledge_automatic_ai_alert(alert_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{64}", alert_id):
            raise HTTPException(404, "自动 AI 告警不存在。")
        try:
            value = automatic_store.ack_ai_alert(alert_id)
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(503, "自动 AI 告警暂时不可用。") from None
        if value is None:
            raise HTTPException(404, "自动 AI 告警不存在。")
        return value

    @application.get("/api/vulnerability-watch/status", dependencies=protected)
    def vulnerability_status() -> dict:
        try:
            return {
                **vulnerability_monitor.status(),
                "webhook": vulnerability_webhook_worker.status(),
            }
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="定期漏洞观察状态暂时不可用。") from None

    @application.get("/api/vulnerability-watch/alerts", dependencies=protected)
    def vulnerability_alerts() -> list[dict]:
        try:
            return vulnerability_store.list_events(
                scope_hashes=list(vulnerability_monitor.scopes.values())
            )
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="漏洞观察告警暂时不可用。") from None

    def find_vulnerability_alert(identifier: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise HTTPException(status_code=404, detail="漏洞观察告警不存在。")
        try:
            result = vulnerability_store.get_event(identifier)
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="漏洞观察证据暂时不可用。") from None
        if result is None:
            raise HTTPException(status_code=404, detail="漏洞观察告警不存在。")
        return result

    @application.get("/api/vulnerability-watch/alerts/{alert_id}", dependencies=protected)
    def vulnerability_alert_detail(alert_id: str) -> dict:
        return find_vulnerability_alert(alert_id)

    @application.post("/api/vulnerability-watch/alerts/{alert_id}/ack", dependencies=protected)
    def vulnerability_acknowledge(alert_id: str, _body: AcknowledgeAlert) -> dict:
        find_vulnerability_alert(alert_id)
        try:
            result = vulnerability_store.acknowledge(alert_id)
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="已阅未保存，请稍后重新读取。") from None
        if result is None:
            raise HTTPException(status_code=404, detail="漏洞观察告警不存在。")
        return result

    @application.get(
        "/api/vulnerability-watch/observations/{observation_id}", dependencies=protected
    )
    def vulnerability_observation(observation_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{32}", observation_id):
            raise HTTPException(status_code=404, detail="漏洞观察记录不存在。")
        try:
            result = vulnerability_store.get_observation(observation_id)
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="漏洞观察记录暂时不可用。") from None
        if result is None:
            raise HTTPException(status_code=404, detail="漏洞观察记录不存在。")
        return result

    @application.get("/api/security/status", dependencies=protected)
    def security_status() -> dict[str, object]:
        try:
            return security_monitor.status()
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="安全观察状态暂时不可用。") from None

    @application.get("/api/security/alerts", dependencies=protected)
    def security_alerts() -> list[dict]:
        try:
            results = security_store.list_alerts() + web_security_store.list_alerts()
            return sorted(
                results, key=lambda value: (value["last_seen"], value["id"]), reverse=True
            )[:100]
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="安全告警存储暂时不可用。") from None

    def alert_store(alert_id: str):
        try:
            for candidate in (security_store, web_security_store):
                if candidate.get_alert(alert_id) is not None:
                    return candidate
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="安全告警读取暂时不可用。") from None
        raise HTTPException(status_code=404, detail="告警不存在。")

    def find_security_alert(alert_id: str) -> dict:
        try:
            result = alert_store(alert_id).get_alert(alert_id)
            if result is None:
                raise HTTPException(status_code=404, detail="告警不存在。")
            result["observation"] = alert_store(alert_id).get_observation(result["observation_id"])
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="观察证据读取暂时不可用。") from None
        return result

    def security_analysis_digest(detail: dict) -> str:
        binding = {
            "evidence_digest": input_digest(detail),
            "provider": settings.ai_base_url,
            "model": settings.ai_model,
        }
        return hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @application.get("/api/security/alerts/{alert_id}", dependencies=protected)
    def security_alert_detail(alert_id: str) -> dict:
        result = find_security_alert(alert_id)
        try:
            saved = security_ai_store.get(alert_id)
            matches = saved is not None and saved["input_digest"] == security_analysis_digest(
                result
            )
            result["analysis"] = saved["analysis"] if matches else None
            result["analysis_input_hash"] = saved["input_digest"] if saved else None
            result["analysis_stale"] = saved is not None and not matches
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="观察证据读取暂时不可用。") from None
        return result

    @application.post("/api/security/alerts/{alert_id}/ack", dependencies=protected)
    def security_alert_acknowledge(alert_id: str, _body: AcknowledgeAlert) -> dict:
        find_security_alert(alert_id)
        try:
            result = alert_store(alert_id).acknowledge(alert_id)
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="告警已阅状态暂时无法保存。") from None
        if result is None:
            raise HTTPException(status_code=404, detail="告警不存在。")
        return result

    @application.get("/api/security/alerts/{alert_id}/analysis-input", dependencies=protected)
    def security_analysis_preview(alert_id: str) -> dict:
        detail = find_security_alert(alert_id)
        try:
            guard_alert_source(detail, resolve_ai_settings(settings))
            summary = analysis_input(detail)
        except AIEgressBlocked as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        return {
            "input": summary,
            "input_digest": security_analysis_digest(detail),
            "model_name": provider_status(settings)["model_name"],
            "provider_host": urlsplit(settings.ai_base_url).hostname
            if settings.ai_base_url
            else None,
        }

    @application.post("/api/security/alerts/{alert_id}/analyze", dependencies=protected)
    def security_analyze(alert_id: str, body: SecurityAnalysisRequest) -> dict:
        if not ai_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有模型请求正在运行。")
        try:
            detail = find_security_alert(alert_id)
            digest = security_analysis_digest(detail)
            if digest != body.expected_input_digest:
                raise HTTPException(status_code=409, detail="告警证据已变化，请重新预览并确认。")
            result = analyze_alert(detail, settings)
            if security_analysis_digest(find_security_alert(alert_id)) != digest:
                raise HTTPException(
                    status_code=409, detail="分析期间证据已更新，结果未附加到当前告警。"
                )
            result["input_digest"] = digest
            if result.get("status") == "completed":
                try:
                    security_ai_store.save(alert_id, digest, result)
                except (sqlite3.Error, ValueError):
                    raise HTTPException(
                        status_code=503, detail="分析结果暂时无法保存，原告警保留。"
                    ) from None
            return result
        finally:
            ai_lock.release()

    @application.get("/api/security/observations/{observation_id}", dependencies=protected)
    def security_observation(observation_id: str) -> dict:
        try:
            result = security_store.get_observation(observation_id)
            if result is None:
                result = web_security_store.get_observation(observation_id)
        except (sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="观察证据读取暂时不可用。") from None
        if result is None:
            raise HTTPException(status_code=404, detail="观察记录不存在或已超过保留范围。")
        return result

    @application.get("/api/hosts", dependencies=protected)
    def public_hosts() -> list[dict[str, object]]:
        result = {
            (host.public.id, host.public.source): {
                **host.public.model_dump(mode="json"),
                "compose_discovery_configured": host.compose_project is not None,
                "container_binding_confirmed": host.container_binding_confirmed,
                "nginx_dependencies_configured": host.nginx_scope_digest is not None,
                "nginx_dependency_scope_digest": host.nginx_scope_digest,
                "nginx_dependency_binding_digest": dependency_binding_digest(host),
                **(
                    {"nginx_path_observation_binding_digest": path_binding}
                    if (path_binding := path_observation_binding_digest(host)) is not None
                    else {}
                ),
                **(
                    {
                        "compose_volume_scope_digest": host.compose_volume_scope_digest,
                        "compose_volume_binding_digest": compose_volume_binding_digest(host),
                    }
                    if host.compose_volume_scope_digest is not None
                    else {}
                ),
                **(
                    {
                        "container_restart_configured": True,
                        "container_restart_binding_digest": container_restart_targets[
                            host.public.id
                        ].target_scope,
                    }
                    if host.public.id in container_restart_targets
                    else {}
                ),
                **(
                    {
                        "nginx_action_configured": True,
                        "nginx_action_binding_digest": nginx_action_targets[
                            host.public.id
                        ].target_scope,
                    }
                    if host.public.id in nginx_action_targets
                    else {}
                ),
            }
            for host in hosts.values()
        }
        for sample in list_samples():
            host, _ = collect_replay(sample["id"])
            result.setdefault((host.id, host.source), host.model_dump(mode="json"))
        return list(result.values())

    @application.post(
        "/api/host-onboarding/prepare", response_model=HostOnboarding, dependencies=protected
    )
    def host_onboarding(body: HostOnboardingRequest) -> HostOnboarding:
        try:
            return prepare_host_onboarding(body)
        except HostOnboardingError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None

    @application.post(
        "/api/hosts/{host_id}/nginx-dependencies",
        response_model=NginxDependencies,
        dependencies=protected,
    )
    def nginx_dependencies(host_id: str, _body: HostPreflightRequest) -> NginxDependencies:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if registered.nginx_scope_digest is None or registered.compose_project is None:
            raise HTTPException(status_code=409, detail="尚未登记 Nginx 范围及精确只读策略。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_nginx_dependencies(registered, settings)
        except (OSError, ValueError):
            raise HTTPException(status_code=503, detail="Nginx 依赖证据暂时不可用。") from None
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/nginx-path-observation",
        response_model=NginxPathObservation,
        dependencies=protected,
    )
    def nginx_path_observation(host_id: str, _body: HostPreflightRequest) -> NginxPathObservation:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        binding = path_observation_binding_digest(registered)
        if binding is None:
            raise HTTPException(status_code=409, detail="尚未登记 Nginx 范围和只读业务检查。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            result = run_business_readiness(registered)
            return NginxPathObservation(
                host_id=host_id,
                binding_digest=binding,
                observed_at=datetime.now(UTC),
                status=result.status,
                checks=result.checks,
            )
        except (OSError, ValueError):
            raise HTTPException(status_code=503, detail="登记路径响应暂时不可用。") from None
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/compose-discovery",
        response_model=ComposeDiscovery,
        dependencies=protected,
    )
    def compose_discovery(host_id: str, _body: HostPreflightRequest) -> ComposeDiscovery:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if registered.compose_project is None:
            raise HTTPException(status_code=409, detail="尚未登记 Compose 项目及精确只读策略。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_compose_discovery(registered, registered.compose_project)
        except (OSError, ValueError):
            raise HTTPException(status_code=503, detail="Compose 只读发现暂时不可用。") from None
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/compose-volume-metadata",
        response_model=ComposeVolumeObservation,
        dependencies=protected,
    )
    def compose_volume_metadata(
        host_id: str, _body: HostPreflightRequest
    ) -> ComposeVolumeObservation:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if compose_volume_binding_digest(registered) is None:
            raise HTTPException(status_code=409, detail="尚未登记 Compose 卷范围及精确只读策略。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_compose_volume_metadata(registered, settings)
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/compose-discovery/preview",
        response_model=ComposeRegistrationPreview,
        dependencies=protected,
    )
    def compose_discovery_preview(
        host_id: str,
        body: ComposeSelection,
    ) -> ComposeRegistrationPreview:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if registered.compose_project is None:
            raise HTTPException(status_code=409, detail="尚未登记 Compose 项目及精确只读策略。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            current = run_compose_discovery(registered, registered.compose_project)
            return preview_compose_registration(current, body)
        except DiscoveryRefused:
            raise HTTPException(
                status_code=409, detail="候选或端口已变化，请重新运行只读发现。"
            ) from None
        except (OSError, ValueError):
            raise HTTPException(status_code=503, detail="登记预览暂时不可用。") from None
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/preflight", response_model=HostPreflight, dependencies=protected
    )
    def preflight_host(host_id: str, _body: HostPreflightRequest) -> HostPreflight:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_host_preflight(registered)
        except (OSError, ValueError):
            raise HTTPException(status_code=503, detail="接入预检暂时不可用。") from None
        finally:
            investigation_lock.release()

    @application.post(
        "/api/hosts/{host_id}/business-readiness",
        response_model=BusinessReadiness,
        dependencies=protected,
    )
    def business_readiness(host_id: str, _body: HostPreflightRequest) -> BusinessReadiness:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_business_readiness(registered)
        finally:
            investigation_lock.release()

    @application.get(
        "/api/hosts/{host_id}/ssh-defense/actions",
        response_model=DefenseActions,
        dependencies=protected,
    )
    def ssh_defense_actions(host_id: str) -> DefenseActions:
        registered = hosts.get(host_id)
        if registered is None or registered.public.source != "ssh":
            raise HTTPException(status_code=404, detail="SSH 主机未登记。")
        try:
            return DefenseActions(
                host_id=host_id,
                actions=[
                    DefenseAction(
                        action_id=action,
                        last_observed=defense_status_store.get(registered, action),
                    )
                    for action in registered.ssh_defense_action_ids
                ]
                if defense_status_store is not None
                else [],
            )
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="防护观察记录暂时不可读取。") from None

    @application.post(
        "/api/hosts/{host_id}/ssh-defense/actions/{action_id}/status",
        response_model=DefenseQuery,
        dependencies=protected,
    )
    def ssh_defense_action_status(
        host_id: str, action_id: str, _body: HostPreflightRequest
    ) -> DefenseQuery:
        registered = hosts.get(host_id)
        if (
            registered is None
            or registered.public.source != "ssh"
            or action_id not in registered.ssh_defense_action_ids
            or defense_status_store is None
        ):
            raise HTTPException(status_code=404, detail="隔离防护动作未登记。")
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有只读检查正在运行，请稍后重试。")
        try:
            return run_defense_status(registered, action_id, defense_status_store)
        except (OSError, sqlite3.Error, ValueError):
            raise HTTPException(status_code=503, detail="防护观察记录暂时不可读取。") from None
        finally:
            investigation_lock.release()

    @application.get("/api/samples", dependencies=protected)
    def samples() -> list[dict[str, str]]:
        return list_samples()

    def collect_investigation(
        body: InvestigationRequest, *, required_scope: str | None = None
    ) -> Report:
        try:
            if body.source == "replay":
                if not body.sample_id:
                    raise HTTPException(status_code=422, detail="回放调查需要指定样例。")
                sample = next(
                    (item for item in list_samples() if item["id"] == body.sample_id), None
                )
                if sample is None:
                    raise HTTPException(status_code=404, detail="样例不存在。")
                if sample["scenario"] != body.scenario:
                    raise HTTPException(status_code=422, detail="请求场景与样例场景不一致。")
                host, collection = collect_replay(body.sample_id)
                if body.host_id is not None and body.host_id != host.id:
                    raise HTTPException(status_code=422, detail="样例与指定主机不一致。")
            else:
                if body.sample_id is not None or not body.host_id:
                    raise HTTPException(status_code=422, detail="SSH 调查仅接受已登记的主机标识。")
                registered = hosts.get(body.host_id)
                if registered is None:
                    raise HTTPException(status_code=404, detail="SSH 主机未登记。")
                if required_scope is not None and not matches_host_scope(
                    registered.public, required_scope
                ):
                    raise HTTPException(status_code=409, detail="目标登记范围已变化，请重新核对。")
                host, collection = registered.public, collect_ssh(registered, body.scenario)
            blocked = None
            try:
                guard_source(collection.model_dump(mode="json"), resolve_ai_settings(settings))
            except AIEgressBlocked as error:
                blocked = error.code
            clean = sanitize_collection(collection)
            report = diagnose(body.scenario, host, clean)
            if collection.nginx_error_window_blocked:
                blocked = blocked or "unclassified_payload"
            report.ai_egress_block_reason = blocked or report.ai_egress_block_reason
            report.target = host
            report.scope_hash = scope_for(host)
            # Evaluate before redaction: replacement markers are not original response content.
            report.verification = evaluate_health(host, collection) + report.verification
            report.comparison = compare(
                report, baseline_store.latest(report.source, report.host_id, report.scenario)
            )
            return report
        except HTTPException:
            raise
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="报告存储暂时不可用。") from error
        except Exception as error:
            raise HTTPException(
                status_code=500,
                detail="调查未完成，未执行修复或封禁。请检查服务端运行状态。",
            ) from error

    def save_investigation(report: Report, *, capture_access: bool = False) -> None:
        try:
            registered = hosts.get(report.host_id) if capture_access else None
            profile = access_profile(report, registered) if registered is not None else None
            container_profile = container_recheck_profile(report, registered)
            if profile is not None or container_profile is not None:
                active = False
                with suppress(OSError, ValueError):
                    active = load_hosts(settings).get(report.host_id) == registered
                if active:
                    store.save(
                        report, access_profile=profile, container_recheck_profile=container_profile
                    )
                    return
            store.save(report)
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="报告存储暂时不可用。") from error
        except Exception as error:
            raise HTTPException(
                status_code=500,
                detail="调查未完成，未执行修复或封禁。请检查服务端运行状态。",
            ) from error

    @application.post("/api/investigations", response_model=Report, dependencies=protected)
    def investigate(body: InvestigationRequest) -> Report:
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有调查正在运行，请稍后重试。")
        try:
            registered = (
                hosts.get(body.host_id)
                if body.source == "ssh"
                and body.scenario == "container_restart"
                and body.host_id is not None
                and body.sample_id is None
                else None
            )
            before = (
                collect_generation(registered)
                if registered is not None and compose_generation_binding_digest(registered)
                else None
            )
            report = collect_investigation(body)
            current = None
            if (
                registered is not None
                and before is not None
                and report.compatibility.status == "compatible"
            ):
                fields, _, _ = snapshot(report)
                if (
                    fields.get("container.name") == registered.public.container_name
                    and "container.status" in fields
                    and "container.image_id" in fields
                ):
                    current = stable_observation(before, collect_generation(registered))
            save_investigation(report, capture_access=True)
            if current is not None:
                # Optional evidence stays unavailable if the adjunct cannot be committed.
                with suppress(sqlite3.Error, ValueError):
                    generation_store.save(report.id, current)
            return report
        finally:
            investigation_lock.release()

    @application.get("/api/reports", dependencies=protected)
    def reports() -> list[dict[str, object]]:
        try:
            return store.list()
        except (sqlite3.Error, ValueError) as error:
            raise HTTPException(status_code=503, detail="报告存储暂时不可用。") from error

    @application.get("/api/reports/{report_id}", response_model=Report, dependencies=protected)
    def report_detail(report_id: str) -> Report:
        return find_report(report_id)

    @application.get(
        "/api/reports/{report_id}/compose-generation",
        response_model=GenerationComparison,
        dependencies=protected,
    )
    def report_compose_generation(report_id: str) -> GenerationComparison:
        report = find_report(report_id)
        baseline_id = report.comparison.baseline_report_id
        if (
            report.source != "ssh"
            or report.scenario != "container_restart"
            or baseline_id is None
            or report.comparison.status not in {"compared", "incomplete"}
        ):
            return GenerationComparison()
        try:
            baseline = baseline_store.for_report(baseline_id)
            if baseline is None or baseline.id != report.comparison.baseline_id:
                return GenerationComparison()
            return generation_store.compare_to_baseline(report.id, baseline)
        except (sqlite3.Error, ValueError):
            raise HTTPException(503, "Compose 代次观察暂时不可读取。") from None

    @application.get("/api/baselines", dependencies=protected)
    def baselines() -> list[dict[str, object]]:
        try:
            return baseline_store.list()
        except (sqlite3.Error, ValueError) as error:
            raise HTTPException(status_code=503, detail="观测基线暂时不可用。") from error

    @application.post(
        "/api/reports/{report_id}/baseline", response_model=BaselineInfo, dependencies=protected
    )
    def save_baseline(report_id: str, body: BaselineRequest) -> BaselineInfo:
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="调查正在进行，请稍后保存观测基线。")
        try:
            return baseline_store.save(find_report(report_id))
        except HTTPException:
            raise
        except ValueError as error:
            raise HTTPException(
                status_code=409,
                detail="该报告缺少有效目标范围或可解释的完整观测字段；请重新调查后保存。",
            ) from error
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="观测基线暂时不可用。") from error
        finally:
            investigation_lock.release()

    @application.get("/api/reports/{report_id}/export", dependencies=protected)
    def export(report_id: str) -> Response:
        report = find_report(report_id)
        filename = re.sub(r"[^a-zA-Z0-9_-]", "_", report.id)[:80]
        try:
            document = report_markdown(report)
        except ValueError:
            raise HTTPException(409, "报告磁盘聚合对照未通过完整核验，未导出。") from None
        return Response(
            document,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="opsark-{filename}.md"'},
        )

    @application.get("/api/reports/{report_id}/handoff-options", dependencies=protected)
    def handoff_options(report_id: str) -> dict:
        report = find_report(report_id)
        jobs = []
        if (
            report.source != "ssh"
            or not re.fullmatch(r"[0-9a-f]{64}", report.scope_hash)
            or report.created_at.utcoffset() is None
        ):
            return {"jobs": [], "rechecks": []}
        try:
            for job in patch_store.list_jobs():
                if job["host_id"] != report.host_id or job.get("status") not in (
                    ACTIVE_STATES | TERMINAL_STATES
                ):
                    continue
                audit = patch_store.get_handoff_audit(report.host_id, job["job_id"])
                if audit is None or not report_matches_handoff_scope(
                    report, audit["host_id"], audit["host_scope"]
                ):
                    continue
                try:
                    at = datetime.fromisoformat(audit["approved_at"])
                except (TypeError, ValueError):
                    continue
                if at.utcoffset() is None or at < report.created_at:
                    continue
                jobs.append(
                    {
                        "id": job["job_id"],
                        "status": job["status"],
                        "at": at.astimezone(UTC).isoformat(),
                    }
                )
                if len(jobs) == 20:
                    break
            return {"jobs": jobs, "rechecks": store.handoff_rechecks(report) if jobs else []}
        except (OSError, ValueError, sqlite3.Error):
            raise HTTPException(503, "交接记录暂时不可读取。") from None

    def bound_handoff_records(report: Report, job_id: str) -> tuple[dict, dict, list[dict]]:
        if report.source != "ssh":
            raise HTTPException(409, "回放报告只能导出调查摘要。")
        job = patch_store.get_job(report.host_id, job_id)
        audit = patch_store.get_handoff_audit(report.host_id, job_id)
        if (
            job is None
            or audit is None
            or not report_matches_handoff_scope(report, audit["host_id"], audit["host_scope"])
        ):
            raise ValueError("Unlinked handoff job")
        activations = [
            row
            for row in activation_store.list()
            if row["host_id"] == report.host_id and row["job_id"] == job_id
        ]
        return job, audit, activations

    def recheck_host(
        report: Report, timeline: HandoffTimeline, host_scope: str, *, bodyless_required: bool
    ) -> HostConfig | None:
        registered = hosts.get(report.host_id)
        if (
            timeline.recheck_after is None
            or timeline.recheck_after >= datetime.now(UTC)
            or registered is None
            or registered.public.source != "ssh"
            or not matches_host_scope(registered.public, host_scope)
        ):
            return None
        if registered.business_checks:
            return (
                registered
                if any(check.read_only_confirmed for check in registered.business_checks)
                else None
            )
        if not bodyless_required and any(
            check.read_only_confirmed for check in registered.public.health_checks
        ):
            return registered
        return None

    def recheck_row(
        record: Report | BusinessHandoffRecheck, timeline: HandoffTimeline
    ) -> HandoffRecheckRow:
        at = record.finished_at if isinstance(record, BusinessHandoffRecheck) else record.created_at
        return HandoffRecheckRow(
            id=record.id,
            at=at.astimezone(UTC),
            status=timeline.recheck_status,
            configured_checks=timeline.configured_checks,
            matched_checks=timeline.matched_checks,
        )

    def run_bodyless_handoff_recheck(
        report: Report, job_id: str, audit: dict, registered: HostConfig
    ) -> HandoffRecheckRow:
        approval = handoff_approval_digest(audit)
        profile = business_profile_digest(registered)
        started = datetime.now(UTC)
        result = run_business_readiness(registered)
        finished = datetime.now(UTC)
        if result.host_id != report.host_id or [row.id for row in result.checks] != [
            check.id for check in registered.business_checks
        ]:
            raise ValueError("Unexpected business recheck receipt")
        receipt = BusinessHandoffRecheck(
            id="br-" + uuid4().hex,
            report_id=report.id,
            host_id=report.host_id,
            job_id=job_id,
            host_scope=audit["host_scope"],
            approval_digest=approval,
            profile_digest=profile,
            started_at=started,
            finished_at=finished,
            checks=[row.status for row in result.checks],
        )
        # The patch and activation monitors can advance the ledger while SSH is open.
        job, latest_audit, activations = bound_handoff_records(report, job_id)
        projection = build_handoff_timeline(
            report, job, latest_audit, receipt, activations=activations
        )
        latest_host = recheck_host(
            report, projection, latest_audit["host_scope"], bodyless_required=True
        )
        if (
            latest_host is None
            or business_profile_digest(latest_host) != profile
            or projection.recheck_after is None
            or started <= projection.recheck_after
        ):
            raise HTTPException(409, "原任务或登记范围已变化，请重新核对后复验。")
        store.save_handoff_receipt(receipt)
        return recheck_row(receipt, projection)

    @application.get("/api/reports/{report_id}/handoff-rechecks", dependencies=protected)
    def handoff_rechecks(
        report_id: str, job_id: str = Query(pattern=r"^[0-9a-f]{32}$")
    ) -> HandoffRechecks:
        report = find_report(report_id)
        try:
            job, audit, activations = bound_handoff_records(report, job_id)
            timeline = build_handoff_timeline(report, job, audit, activations=activations)
            receipts = store.handoff_receipts(report.id, job_id)
            legacy = (
                store.handoff_rechecks(
                    report, after=timeline.recheck_after, host_scope=audit["host_scope"]
                )
                if timeline.recheck_after is not None
                else []
            )
            records: list[Report | BusinessHandoffRecheck] = list(receipts)
            for candidate in legacy:
                try:
                    recheck = store.get(candidate["id"])
                except ValueError:
                    continue
                if recheck is not None:
                    records.append(recheck)
            rows = []
            for record in records:
                try:
                    projection = build_handoff_timeline(
                        report, job, audit, record, activations=activations
                    )
                    rows.append(recheck_row(record, projection))
                except ValueError:
                    continue
            rows.sort(key=lambda row: (row.at, row.id), reverse=True)
            registered = recheck_host(
                report, timeline, audit["host_scope"], bodyless_required=bool(receipts)
            )
            return HandoffRechecks(can_run=registered is not None, rechecks=rows[:20])
        except ValueError:
            raise HTTPException(409, "所选任务与本次调查的绑定未能核实。") from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "交接记录暂时不可读取。") from None

    @application.post(
        "/api/reports/{report_id}/handoff-rechecks", status_code=201, dependencies=protected
    )
    def run_handoff_recheck(report_id: str, body: HandoffRecheckRequest) -> HandoffRecheckRow:
        if not investigation_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有调查正在运行，请稍后重试。")
        try:
            report = find_report(report_id)
            job, audit, activations = bound_handoff_records(report, body.job_id)
            timeline = build_handoff_timeline(report, job, audit, activations=activations)
            registered = recheck_host(
                report,
                timeline,
                audit["host_scope"],
                bodyless_required=store.has_handoff_receipts(report.id, body.job_id),
            )
            if registered is None:
                raise HTTPException(409, "当前目标或任务尚不满足只读业务复验条件。")
            if registered.business_checks:
                return run_bodyless_handoff_recheck(report, body.job_id, audit, registered)
            recheck = collect_investigation(
                InvestigationRequest(
                    source="ssh", host_id=report.host_id, scenario=report.scenario
                ),
                required_scope=audit["host_scope"],
            )
            # Re-read the local ledger after collection in case a concurrent update changed it.
            job, audit, activations = bound_handoff_records(report, body.job_id)
            timeline = build_handoff_timeline(report, job, audit, recheck, activations=activations)
            if timeline.recheck_after is None:
                raise HTTPException(409, "原任务状态已变化，请重新核对后复验。")
            row = recheck_row(recheck, timeline)
            save_investigation(recheck)
            return row
        except ValueError:
            raise HTTPException(409, "所选任务或复验记录与本次调查的绑定未能核实。") from None
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "交接记录暂时不可读取。") from None
        finally:
            investigation_lock.release()

    @application.get("/api/reports/{report_id}/handoff", dependencies=protected)
    def export_handoff(
        report_id: str,
        job_id: str | None = Query(default=None, pattern=r"^[0-9a-f]{32}$"),
        recheck_report_id: str | None = Query(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$"),
    ) -> Response:
        report = find_report(report_id)
        try:
            validate_disk_comparison(report)
        except ValueError:
            raise HTTPException(409, "报告磁盘聚合对照未通过完整核验，未导出。") from None
        timeline = None
        if recheck_report_id is not None and job_id is None:
            raise HTTPException(422, "关联复验前需要选择原任务。")
        if job_id is not None:
            try:
                job, audit, activations = bound_handoff_records(report, job_id)
                recheck: Report | BusinessHandoffRecheck | None = None
                if recheck_report_id is not None:
                    if re.fullmatch(r"br-[0-9a-f]{32}", recheck_report_id):
                        recheck = store.get_handoff_receipt(report.id, job_id, recheck_report_id)
                        if recheck is None:
                            raise HTTPException(404, "复验记录不存在。")
                    else:
                        recheck = find_report(recheck_report_id)
                timeline = build_handoff_timeline(
                    report, job, audit, recheck, activations=activations
                )
            except ValueError:
                raise HTTPException(409, "所选任务或复验记录与本次调查的绑定未能核实。") from None
            except (OSError, sqlite3.Error):
                raise HTTPException(503, "交接记录暂时不可读取。") from None
        return Response(
            handoff_markdown(report, timeline),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="opsark-handoff.md"'},
        )

    @application.post(
        "/api/reports/{report_id}/explain",
        response_model=AIExplanation,
        dependencies=protected,
    )
    def explain_report(report_id: str, body: ExplainRequest) -> AIExplanation:
        report = find_report(report_id)
        if not provider_status(settings)["configured"]:
            raise HTTPException(status_code=409, detail="尚未配置模型，未发送任何报告数据。")
        if not ai_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="已有 AI 解释请求正在运行。")
        try:
            try:
                explanation = explain(report, settings)
            except Exception:  # noqa: BLE001 -- provider errors must not expose credentials in API errors.
                explanation = AIExplanation(
                    status="failed", text="AI 解释暂时不可用，原始诊断保留。"
                )
            updated = store.set_ai(report.id, explanation)
            if updated is None:
                raise HTTPException(status_code=404, detail="报告不存在。")
            return updated.ai
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="报告存储暂时不可用。") from error
        finally:
            ai_lock.release()

    def asset(filename: str, media_type: str) -> FileResponse:
        path = web_dir / filename
        if not path.is_file():
            raise HTTPException(status_code=404, detail="控制台资源尚未就绪。")
        return FileResponse(path, media_type=media_type)

    @application.get("/", include_in_schema=False)
    @application.get("/index.html", include_in_schema=False)
    def index() -> FileResponse:
        return asset("index.html", "text/html")

    @application.get("/app.js", include_in_schema=False)
    def javascript() -> FileResponse:
        return asset("app.js", "text/javascript")

    @application.get("/defense.js", include_in_schema=False)
    def defense_javascript() -> FileResponse:
        return asset("defense.js", "text/javascript")

    @application.get("/nginx-dependencies.js", include_in_schema=False)
    def nginx_dependencies_script() -> Response:
        return asset("nginx-dependencies.js", "text/javascript")

    @application.get("/compose-volumes.js", include_in_schema=False)
    def compose_volumes_script() -> Response:
        return asset("compose-volumes.js", "text/javascript")

    @application.get("/nginx-actions.js", include_in_schema=False)
    def nginx_actions_script() -> Response:
        return asset("nginx-actions.js", "text/javascript")

    @application.get("/container-restarts.js", include_in_schema=False)
    def container_restarts_script() -> Response:
        return asset("container-restarts.js", "text/javascript")

    @application.get("/styles.css", include_in_schema=False)
    def stylesheet() -> FileResponse:
        return asset("styles.css", "text/css")

    return application


app = create_app()
