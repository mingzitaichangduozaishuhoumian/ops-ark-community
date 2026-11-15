"""Render a customer handoff from classified observations and typed status fields."""

import re
from collections import Counter
from datetime import UTC

from opsark.ai import classify_finding
from opsark.handoff_timeline import HandoffTimeline
from opsark.models import Finding, Report
from opsark.nginx_error_window import metadata_line

_SOURCES = {"replay": "回放样本（合成数据）", "ssh": "SSH 只读采集"}
_SCENARIOS = {
    "web_502": "网站 502 与上游异常",
    "disk": "磁盘空间与 inode",
    "container_restart": "容器异常重启",
    "ssh_security": "SSH 认证异常",
}
_STATUSES = {
    "needs_attention": "发现需关注的线索",
    "inconclusive": "证据不足，结论待定",
    "no_issue_detected": "本次已覆盖检查未发现同类异常",
}
_COMPATIBILITY = {"compatible": "环境预检通过", "unsupported": "环境超出支持范围"}
_CHECKS = {
    "connection": "连接检查",
    "os_release": "系统识别",
    "platform_tools": "采集工具预检",
    "nginx_status": "Nginx 服务状态",
    "nginx_errors": "Nginx 错误片段",
    "nginx_config_hash": "Nginx 配置摘要检查",
    "listeners": "端口监听快照",
    "container_state": "容器运行状态",
    "container_logs": "容器日志片段",
    "memory_events": "内存事件",
    "disk_bytes": "文件系统容量",
    "disk_inodes": "文件系统 inode",
    "disk_directories": "目录占用抽样",
    "ssh_auth": "SSH 认证事件",
}
_HTTP_CHECK = re.compile(r"http_[a-z][a-z0-9_]{0,39}")
_EVIDENCE_STATUS = {
    "ok": "已取得",
    "error": "采集出错",
    "timeout": "采集超时",
    "permission_denied": "采集权限不足",
    "unavailable": "未取得",
}
_VERIFICATION_STATUS = {
    "not_run": "未执行",
    "uncovered": "未覆盖",
    "passed": "登记条件符合",
    "failed": "登记条件未满足",
    "error": "检查出错",
}
_COMPARISON = {
    "no_baseline": "未建立可比较的基线",
    "compared": "已对照观测基线",
    "incomplete": "观测对照有缺口",
    "scope_changed": "范围变化，已停止对照",
}
_FINDINGS = {
    "os_identified": "已取得系统标识",
    "nginx_state": "已观测 Nginx 服务状态",
    "nginx_unavailable": "代理层服务不可用需优先核实",
    "upstream_refused": "日志片段出现本机上游连接被拒绝",
    "upstream_timeout": "日志片段出现上游连接超时",
    "container_state": "已观测登记容器状态",
    "container_not_running": "上游容器当前未处于正常运行状态",
    "published_ports_observed": "已取得容器发布端口快照",
    "upstream_port_mismatch": "上游与容器发布端口可能不一致",
    "listeners_observed": "已取得端口监听快照",
    "disk_capacity_observed": "已取得根分区容量快照",
    "disk_capacity_risk": "根分区空间达到关注阈值",
    "inodes_observed": "已取得 inode 使用快照",
    "inode_risk": "inode 余量达到关注阈值",
    "directory_log_usage": "已观测日志目录占用",
    "directory_persistent_usage": "目录样本可能包含持久化业务数据",
    "directory_docker_usage": "已观测 Docker 数据占用",
    "directory_unclassified_usage": "目录用途待维护方确认",
    "restart_count_observed": "已读取容器累计重启计数",
    "exit_code_observed": "已读取容器最近退出状态",
    "memory_limit_observed": "已读取容器内存限制状态",
    "oom_observed": "运行时记录了内存终止标记",
    "oom_candidate": "内存终止是有状态证据支持的候选原因",
    "exit_137_uncertain": "仅凭退出状态无法确定终止原因",
    "application_timeout": "应用日志片段出现连接超时",
    "ssh_auth_failures": "日志片段出现 SSH 认证失败事件",
    "ssh_auth_successes": "日志片段出现 SSH 认证成功事件",
    "ssh_source_failures": "部分认证失败事件可按来源归类",
    "ssh_repeated_failures": "同源重复认证失败需核实授权来源",
    "ssh_success_after_failures": "同源认证失败后出现成功事件，需核实授权",
}
_NEXT_STEPS = {
    "web_502": "核对代理服务、上游监听与容器状态，再按登记条件检查网站响应。",
    "disk": "核对容量与 inode 的变化趋势，确认目录归属和保留要求后再评估清理。",
    "container_restart": "结合退出状态、内存事件与近期变更复核，确认后再审批处置。",
    "ssh_security": "核对访问授权和认证日志覆盖，确认异常范围后再决定处置。",
}
_MAX_EVIDENCE = 20
_MAX_FINDING_TEXT = 512
_PHASE_LABELS = {
    "queued": "原任务已排队",
    "preflight": "正在核验执行条件",
    "downloading": "正在准备软件包",
    "applying": "正在执行",
    "verifying": "正在验证任务",
    "running_overdue": "任务仍待核实",
    "awaiting_transport_verification": "等待管理连接验证",
    "verified": "补丁任务验证通过",
    "installed_restart_pending": "已安装，原任务等待服务激活",
    "reboot_pending": "等待主机重启",
    "verification_failed": "任务验证未通过",
    "failed": "任务失败",
    "rejected": "任务被拒绝",
    "unknown": "任务结果未知",
}
_EVENT_LABELS = {
    "investigation": "原调查已记录",
    "approval": "提交授权记录已保存",
    "native_record": "原任务状态已记录",
    "unknown": "提交结果未知已记录",
    "reconciled": "查询原任务已核实结果",
    "activation": "独立服务激活验证通过",
    "recheck": "独立只读业务复验已记录",
}
_RECHECK_LABELS = {"pending": "待验收", "failed": "复验未通过", "passed": "登记业务复验通过"}


def _timeline_lines(timeline: HandoffTimeline) -> list[str]:
    approval = {"assisted": "人工逐项批准", "automatic": "预先授权"}.get(
        timeline.authorization, "批准方式未核实"
    )
    accepted = "远端原任务已核实" if timeline.native_accepted else "远端受理尚未核实"
    lines = [
        "",
        "## 已绑定的处置记录",
        "",
        f"- {_PHASE_LABELS[timeline.phase]}。",
        f"- {approval}。{accepted}。",
    ]
    event_kinds = {event.kind for event in timeline.events}
    if "unknown" in event_kinds and "reconciled" not in event_kinds:
        lines.append("- 待对账：尚未取得可核实的原任务回执。")
    lines.extend(["", "| 时间（UTC） | 记录 |", "| --- | --- |"])
    for event in timeline.events:
        label = _EVENT_LABELS[event.kind]
        if event.kind == "approval" and timeline.authorization is None:
            label = "提交意图已保存"
        lines.append(f"| {event.at.astimezone(UTC).isoformat(timespec='seconds')} | {label} |")
    return lines


def _count(value: int) -> str:
    return str(value) if value <= 1000 else "1000+"


def _check_name(check_id: str) -> str:
    if _HTTP_CHECK.fullmatch(check_id):
        return "站点即时 HTTP 检查"
    return _CHECKS.get(check_id, "未分类检查")


def _finding_lines(findings: list[Finding], limit: int, evidence_refs: dict[str, int]) -> list[str]:
    rendered = []
    for item in findings[:limit]:
        if len(item.text) > _MAX_FINDING_TEXT:
            continue
        kind = classify_finding(item.text)
        if kind and (label := _FINDINGS.get(kind)):
            refs = sorted(
                {evidence_refs[ref] for ref in item.evidence_ids[:20] if ref in evidence_refs}
            )
            suffix = f"（证据 {'、'.join(map(str, refs))}）" if refs else ""
            rendered.append(f"- {label}{suffix}")
    lines = [f"原报告记录 {_count(len(findings))} 项。"]
    if len(rendered) < len(findings):
        lines.append(f"其中 {_count(len(findings) - len(rendered))} 项未列入本交接版。")
    if not rendered:
        lines.append("没有可在交接版列出的分类条目。")
    return [*lines, "", *rendered]


def handoff_markdown(report: Report, timeline: HandoffTimeline | None = None) -> str:
    """Return bounded Markdown without copying free-form report content."""
    source = _SOURCES.get(report.source, "来源未核实")
    recorded = "未记录时区"
    if report.created_at.utcoffset() is not None:
        recorded = report.created_at.astimezone(UTC).isoformat(timespec="minutes")
    compatibility = _COMPATIBILITY.get(report.compatibility.status, "环境预检结果未确认")
    missing = _count(len(report.missing))
    evidence = report.evidence[:_MAX_EVIDENCE]
    occurrences = Counter(item.id for item in evidence)
    evidence_refs = {
        item.id: index
        for index, item in enumerate(evidence, 1)
        if item.source == report.source and occurrences[item.id] == 1
    }
    lines = ["# OpsArk 客户交接摘要", ""]
    if report.source == "replay":
        lines.extend(["> 回放样本为合成数据，仅用于演练。", ""])
    lines.extend(
        [
            "## 调查概况",
            "",
            "| 项目 | 结果 |",
            "| --- | --- |",
            f"| 调查来源 | {source} |",
            f"| 场景 | {_SCENARIOS.get(report.scenario, '场景未分类')} |",
            f"| 记录时间 | {recorded} |",
            f"| 当前判断 | {_STATUSES.get(report.status, '结论待定')} |",
            f"| 环境预检 | {compatibility} |",
            "",
            "## 已观察事实",
            "",
            *_finding_lines(report.facts, 12, evidence_refs),
            "",
            "## 候选原因（待核实）",
            "",
            *_finding_lines(report.candidates, 8, evidence_refs),
            "",
            "## 证据与覆盖",
            "",
            f"- 原报告证据记录 {_count(len(report.evidence))} 项，缺失信息 {missing} 项。",
            f"- {_COMPARISON.get(report.comparison.status, '基线对照状态未确认')}。"
            f"已记录 {_count(len(report.comparison.changes))} 项观测差异。",
            "- 采集结果限于此次调查范围。权限不足、超时或截断的项目需要补证。",
        ]
    )
    if evidence:
        lines.extend(["", "| 序号 | 检查类别 | 采集状态 |", "| --- | --- | --- |"])
        for index, item in enumerate(evidence, 1):
            status = _EVIDENCE_STATUS.get(item.status, "状态未核实")
            if item.truncated:
                status += "，内容截断"
            if item.source != report.source:
                status = "证据来源与调查不一致，需复核"
            lines.append(f"| {index} | {_check_name(item.check_id)} | {status} |")
        if len(report.evidence) > len(evidence):
            lines.extend(["", f"此处列出前 {len(evidence)} 项。"])
    if report.nginx_error_window is not None:
        lines.extend(["", "- " + metadata_line(report.nginx_error_window)])
    if timeline is not None:
        lines.extend(_timeline_lines(timeline))
    lines.extend(["", "## 验收与恢复状态", ""])
    if timeline is None:
        lines.append("**待验收。** 业务恢复未验收。后续处置和业务复验需另行记录。")
    else:
        lines.append(f"**{_RECHECK_LABELS[timeline.recheck_status]}。**")
        if timeline.configured_checks:
            lines.append(
                f"复验符合 {timeline.matched_checks} / {timeline.configured_checks} 项登记检查。"
            )
        lines.append("本节范围限于登记的即时检查。完整业务恢复和持续观察需另行验收。")
    if report.verification:
        lines.extend(["", "| 序号 | 原调查即时检查 |", "| --- | --- |"])
        for index, item in enumerate(report.verification[:5], 1):
            state = _VERIFICATION_STATUS.get(item.status, "检查状态未核实")
            if item.http_status is not None:
                state += f"（HTTP {item.http_status}）"
            lines.append(f"| {index} | {state} |")
        if len(report.verification) > 5:
            lines.extend(["", "此处列出前 5 项检查。"])
        lines.extend(["", "即时检查只反映登记条件在当时的结果。"])
    lines.extend(
        [
            "",
            "## 建议下一步",
            "",
            f"- {_NEXT_STEPS.get(report.scenario, '先确认调查范围并补齐关键证据。')}",
            "- 如需变更，先确认影响、审批人与验证方式。处置后单独记录业务复验和观察结果。",
        ]
    )
    return "\n".join(lines).strip() + "\n"
