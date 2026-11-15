"""Actual loopback API acceptance for one fresh, explicitly enrolled Web fixture."""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import stat
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

DATA = Path("/app/data")
STAGE = DATA / "acceptance-web"
DESCRIPTOR = STAGE / "descriptor.json"
CHECKPOINT = STAGE / "checkpoint.json"
PROVIDER_KEY = STAGE / "fake-provider-key"
PROVIDER_PROOF = STAGE / "provider-proof.json"
PROVIDER_MODEL = "opsark-web-fixture-503"
PROVIDER_PORT = 18890
SYSTEM_PROMPT_SHA256 = "5409885f663dd5d350e2145b73a77faac11c93993e0d2a38bd9affcaf3a82322"
HOST = "web-burst-kvm"
HEX = re.compile(r"[0-9a-f]{64}")
LIMIT_GAPS = {"journal_record_limit", "projection_event_limit", "projection_output_limit"}
SENSITIVE = {"secret_probe", "repo_probe", "cms_probe", "admin_probe", "traversal_probe"}
SUMMARY_FIELDS = {
    "target_ref",
    "channel",
    "kind",
    "severity",
    "origin",
    "source_ref",
    "source_trust",
    "unique_event_count",
    "evidence_window_event_count",
    "evidence_span_seconds",
    "observation",
    "events",
    "metrics",
    "constraints",
}
EVENT_FIELDS = {
    "id",
    "elapsed_seconds",
    "origin",
    "kind",
    "target_ref",
    "source_ref",
    "method",
    "site_ref",
    "peer_ref",
    "source_trust",
    "http_status",
    "path_class",
    "client_class",
    "request_time_ms",
    "bytes_sent",
    "expected_error",
}


class Refused(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_provider_field")
        result[key] = value
    return result


def read(path, *, limit=65_536):
    require(path.parent == STAGE or path == DATA / "access-token", "private_fixture_path_required")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and not info.st_mode & 0o077
            and 0 < info.st_size <= limit,
            "private_fixture_file_required",
        )
        raw = handle.read(limit + 1)
        require(len(raw) == info.st_size, "private_fixture_file_changed")
        return raw


def write(path, value):
    require(path.parent == STAGE, "private_fixture_path_required")
    if path.exists() or path.is_symlink():
        read(path)
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode()
    require(len(raw) <= 65_536, "private_snapshot_budget")
    pending = path.with_name("." + path.name + "." + secrets.token_hex(6))
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def checkpoint():
    return (
        json.loads(read(CHECKPOINT)) if CHECKPOINT.exists() else {"observations": {}, "phases": {}}
    )


def instant(text):
    value = datetime.fromisoformat(text)
    require(value.utcoffset() is not None, "aware_observation_time_required")
    return value.timestamp()


def controller_generation():
    namespace = Path("/proc/self/ns/pid").stat()
    started = int(Path("/proc/1/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[19])
    return {
        "pid_namespace_dev": namespace.st_dev,
        "pid_namespace_inode": namespace.st_ino,
        "pid1_start_ticks": started,
    }


def context(path):
    require(
        sys.platform == "linux" and os.geteuid() == 10001 and Path("/.dockerenv").is_file(),
        "fresh_unprivileged_controller_required",
    )
    require(path == DESCRIPTOR and path.resolve() == path, "fixed_descriptor_required")
    for folder in (DATA, STAGE):
        info = folder.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "private_new_data_required",
        )
    value = json.loads(read(path))
    require(
        set(value) == {"host_id", "domain", "web_scope_hash", "profile_digest", "data_dir"}
        and value["host_id"] == HOST
        and value["domain"] == "opsark-lab.invalid"
        and value["data_dir"] == str(DATA)
        and all(
            isinstance(value[name], str) and HEX.fullmatch(value[name])
            for name in ("web_scope_hash", "profile_digest")
        ),
        "fixed_web_scope_required",
    )
    return value


class API:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.token = read(DATA / "access-token", limit=1024).decode("ascii").strip()
        require(len(self.token) >= 32, "new_controller_token_required")

    def call(self, method, path, payload=None):
        allowed = (
            method == "GET"
            and (
                path
                in {
                    "/api/security/status",
                    "/api/security/alerts",
                    "/api/automation",
                    "/api/ai/status",
                }
                or re.fullmatch(r"/api/security/observations/[A-Za-z0-9_-]{1,80}", path)
                or re.fullmatch(r"/api/security/alerts/[0-9a-f]{64}(?:/analysis-input)?", path)
            )
            or method == "POST"
            and re.fullmatch(r"/api/security/alerts/[0-9a-f]{64}/analyze", path)
        )
        require(allowed, "readonly_or_explicit_analysis_endpoint_required")
        connection = http.client.HTTPConnection("127.0.0.1", 8010, timeout=25)
        try:
            headers = {"Authorization": "Bearer " + self.token}
            if payload is not None:
                headers["Content-Type"] = "application/json"
            connection.request(
                method, path, None if payload is None else json.dumps(payload), headers
            )
            response = connection.getresponse()
            raw = response.read(1_048_577)
            require(
                response.status == 200
                and len(raw) <= 1_048_576
                and response.getheader("Cache-Control") == "no-store",
                "actual_api_request_failed",
            )
            return json.loads(raw)
        finally:
            connection.close()

    def boundaries(self):
        mode = self.call("GET", "/api/automation")
        require(
            mode["mode"] == "manual" and mode["execution_available"] is False,
            "manual_observation_only_required",
        )

    def web(self):
        status = self.call("GET", "/api/security/status")
        require(
            status["enabled"] is True
            and status["web_enabled"] is True
            and status["read_only"] is True
            and type(status["running"]) is bool
            and 30 <= status["interval_seconds"] <= 60,
            "scheduled_web_observer_required",
        )
        require(status["running"] is True, "observer_not_running")
        matches = [row for row in status["hosts"] if row["host_id"] == HOST]
        require(
            len(matches) == 1 and set(matches[0]["channels"]) == {"ssh", "web"},
            "registered_web_host_required",
        )
        web = matches[0]["channels"]["web"]
        require(web["scope_hash"] == self.descriptor["web_scope_hash"], "web_scope_changed")
        return web

    def observation(self, identifier):
        value = self.call("GET", "/api/security/observations/" + identifier)
        require(
            value["id"] == identifier
            and value["host_id"] == HOST
            and value["channel"] == "web"
            and value["scope_hash"] == self.descriptor["web_scope_hash"]
            and value["profile_digest"] == self.descriptor["profile_digest"]
            and value["status"] in {"complete", "degraded", "unavailable"}
            and type(value["raw_records_seen"]) is int
            and 0 <= value["raw_records_seen"] <= 200
            and len(value["events"]) <= 80,
            "native_observation_contract_failed",
        )
        for row in value["events"]:
            require(
                row["host_id"] == HOST
                and row["scope_hash"] == value["scope_hash"]
                and row["origin"] == "controlled_web_probe"
                and row["site_id"] == "lab"
                and row["source_ip"] == row["peer_ip"] == "127.0.0.1"
                and row["method"] == "GET"
                and HEX.fullmatch(row["id"])
                and not (
                    {"uri", "raw_uri", "user_agent", "body", "authorization", "cookie"} & row.keys()
                ),
                "reduced_native_web_events_required",
            )
        return value

    def fresh(self, excluded=(), *, after=None, seconds=145):
        after = time.time() if after is None else after
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                web = self.web()
            except Refused as error:
                if str(error) != "observer_not_running":
                    raise
                time.sleep(0.5)
                continue
            identifier = web.get("last_observation_id")
            if identifier and identifier not in excluded:
                value = self.observation(identifier)
                if instant(value["collected_at"]) >= after:
                    return value
            time.sleep(0.5)
        raise Refused("new_scheduled_observation_not_received")

    def alerts(self):
        return [
            row
            for row in self.call("GET", "/api/security/alerts")
            if row.get("channel") == "web"
            and row["host_id"] == HOST
            and row["scope_hash"] == self.descriptor["web_scope_hash"]
        ]


def alert_metrics(alerts):
    return sorted(
        [
            {key: row[key] for key in ("id", "kind", "unique_event_count", "notification_count")}
            for row in alerts
        ],
        key=lambda row: row["id"],
    )


def remember(state, observation):
    state["observations"][observation["id"]] = {
        "sha256": digest(observation),
        "collected_at": observation["collected_at"],
        "event_ids": sorted(row["id"] for row in observation["events"]),
    }


def history(api, state):
    for identifier, proof in state["observations"].items():
        require(
            digest(api.observation(identifier)) == proof["sha256"],
            "old_observation_changed_or_missing",
        )


def degraded(observation):
    require(
        observation["status"] == "degraded"
        and observation["gaps"]
        and LIMIT_GAPS.intersection(observation["gaps"])
        and set(observation["gaps"]) <= LIMIT_GAPS
        and observation["raw_records_seen"] == 200
        and observation["events"],
        "genuine_bounded_projection_required",
    )


def scan_proof(api, observation):
    alerts = api.alerts()
    require(
        not any(row["kind"] in {"web_error_burst", "web_request_anomaly"} for row in alerts),
        "degraded_ratio_alert_forbidden",
    )
    scans = [row for row in alerts if row["kind"] == "web_scan"]
    require(len(scans) == 1, "supported_scan_lower_bound_required")
    detail = api.call("GET", "/api/security/alerts/" + scans[0]["id"])
    retained = detail["events"]
    require(
        detail["evidence_retained"] is True
        and detail["origin"] == "controlled_web_probe"
        and detail["site_id"] == "lab"
        and detail["source_ip"] == "127.0.0.1"
        and 5 <= detail["unique_event_count"] <= 24
        and detail["coverage_status"] == "degraded"
        and detail["metric_basis"] == "observed_evidence"
        and len([row for row in retained if row["path_class"] in SENSITIVE]) >= 5
        and len({row["path_class"] for row in retained if row["path_class"] in SENSITIVE}) >= 3
        and all(
            row["origin"] == "controlled_web_probe"
            and row["site_id"] == "lab"
            and row["source_ip"] == "127.0.0.1"
            for row in retained
        ),
        "scan_evidence_lower_bound_invalid",
    )
    observed_ids = {row["id"] for row in observation["events"]}
    require(
        bool(observed_ids.intersection(detail["event_ids"])),
        "scan_not_linked_to_native_observation",
    )
    return detail, alert_metrics(alerts)


def native_proof(descriptor):
    value = json.loads(read(STAGE / "native-burst.json"))
    require(
        set(value)
        == {
            "profile_digest",
            "stdout_bytes",
            "stdout_sha256",
            "raw_records_seen",
            "event_count",
            "status",
            "gaps",
        }
        and value["profile_digest"] == descriptor["profile_digest"]
        and type(value["stdout_bytes"]) is int
        and 1 <= value["stdout_bytes"] <= 12288
        and HEX.fullmatch(value["stdout_sha256"])
        and value["raw_records_seen"] == 200
        and type(value["event_count"]) is int
        and 1 <= value["event_count"] <= 80
        and value["status"] == "degraded"
        and LIMIT_GAPS.intersection(value["gaps"])
        and set(value["gaps"]) <= LIMIT_GAPS,
        "independent_native_reader_summary_required",
    )
    return digest(value)


def aliases(value, kind, maximum):
    return (
        value is None
        or isinstance(value, str)
        and re.fullmatch(kind + r"-[1-9][0-9]?", value)
        and int(value.split("-")[1]) <= maximum
    )


def summary_allowed(summary):
    require(
        isinstance(summary, dict)
        and set(summary) == SUMMARY_FIELDS
        and summary["target_ref"] == "target-1"
        and summary["channel"] == "web"
        and summary["kind"] == "web_scan"
        and summary["severity"] == "warning"
        and summary["origin"] == "controlled_web_probe"
        and summary["source_trust"] == "direct_peer"
        and aliases(summary["source_ref"], "source", 41),
        "summary_whitelist_failed",
    )
    for field in ("unique_event_count", "evidence_window_event_count", "evidence_span_seconds"):
        require(
            summary[field] is None
            or type(summary[field]) is int
            and 0 <= summary[field] <= 1_000_000,
            "summary_counter_invalid",
        )
    observation = summary["observation"]
    require(
        set(observation) == {"status", "window_span_seconds", "coverage_gap_count"}
        and observation["status"] == "degraded"
        and observation["window_span_seconds"] == 900
        and type(observation["coverage_gap_count"]) is int
        and 1 <= observation["coverage_gap_count"] <= 20,
        "summary_coverage_invalid",
    )
    metrics = summary["metrics"]
    require(
        set(metrics)
        == {
            "matching_event_count",
            "observed_request_count",
            "window_seconds",
            "coverage_status",
            "metric_basis",
            "retained_evidence_count",
            "referenced_evidence_retained",
            "metric_consistent",
        }
        and metrics["coverage_status"] == "degraded"
        and metrics["metric_basis"] == "observed_evidence"
        and metrics["window_seconds"] == 900
        and metrics["referenced_evidence_retained"] is True
        and metrics["metric_consistent"] is True,
        "summary_metrics_invalid",
    )
    for field in ("matching_event_count", "observed_request_count", "retained_evidence_count"):
        require(
            type(metrics[field]) is int and 0 <= metrics[field] <= 1_000_000,
            "summary_metrics_invalid",
        )
    constraints = summary["constraints"]
    require(
        constraints
        == {
            "actions_executable": False,
            "intrusion_confirmed": False,
            "network_ddos_evidence_available": False,
            "edge_execution_authorization_available": False,
            "shared_egress_possible": True,
            "declared_crawler_is_not_verified": True,
            "retained_samples_are_not_rate_denominator": True,
            "ratio_sample_available": False,
        },
        "summary_authority_invalid",
    )
    events = summary["events"]
    require(
        isinstance(events, list)
        and 5 <= len(events) <= 20
        and metrics["retained_evidence_count"] == len(events),
        "summary_event_budget_invalid",
    )
    for event in events:
        require(
            set(event) == EVENT_FIELDS
            and aliases(event["id"], "event", 20)
            and event["id"] is not None
            and event["target_ref"] == "target-1"
            and event["origin"] == "controlled_web_probe"
            and event["kind"] == "web_request"
            and event["method"] == "GET"
            and aliases(event["source_ref"], "source", 41)
            and aliases(event["peer_ref"], "source", 41)
            and aliases(event["site_ref"], "site", 20)
            and event["source_trust"] == "direct_peer"
            and event["path_class"] in SENSITIVE
            and event["client_class"] == "probe"
            and event["expected_error"] is False,
            "summary_event_whitelist_failed",
        )
        for field, maximum in (
            ("elapsed_seconds", 86400),
            ("http_status", 599),
            ("request_time_ms", 60000),
            ("bytes_sent", 1_000_000_000),
        ):
            require(
                event[field] is None or type(event[field]) is int and 0 <= event[field] <= maximum,
                "summary_event_numeric_invalid",
            )
    return True


def prepare_provider():
    require(not PROVIDER_KEY.exists() and not PROVIDER_PROOF.exists(), "new_fake_provider_required")
    descriptor = os.open(PROVIDER_KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(("opsark-fixture-" + secrets.token_urlsafe(32)).encode("ascii"))
    write(PROVIDER_PROOF, {"requests": 0, "all_payloads_whitelisted": True, "records": []})
    return {"fake_provider_prepared": True, "model": PROVIDER_MODEL, "port": PROVIDER_PORT}


def serve_provider():
    key = read(PROVIDER_KEY, limit=256).decode("ascii")
    require(key.startswith("opsark-fixture-") and len(key) >= 48, "new_fake_credential_required")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def log_message(self, format, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(2)
            valid = False
            request_hash = summary_hash = None
            try:
                require(
                    self.path == "/v1/chat/completions"
                    and self.headers.get("Transfer-Encoding") is None,
                    "fixed_provider_route_required",
                )
                require(
                    hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + key),
                    "fake_auth_required",
                )
                size = int(self.headers.get("Content-Length", "0"))
                require(0 < size <= 65_536, "provider_request_budget")
                raw = self.rfile.read(size)
                require(len(raw) == size, "provider_request_incomplete")
                request_hash = hashlib.sha256(raw).hexdigest()
                body = json.loads(raw, object_pairs_hook=unique_pairs)
                require(
                    set(body) == {"model", "max_tokens", "messages", "response_format"}
                    and body["model"] == PROVIDER_MODEL
                    and type(body["max_tokens"]) is int
                    and 1 <= body["max_tokens"] <= 1600
                    and body["response_format"] == {"type": "json_object"},
                    "provider_body_whitelist_failed",
                )
                messages = body["messages"]
                require(
                    isinstance(messages, list)
                    and len(messages) == 2
                    and all(set(row) == {"role", "content"} for row in messages)
                    and messages[0]["role"] == "system"
                    and messages[1]["role"] == "user"
                    and isinstance(messages[0]["content"], str)
                    and hashlib.sha256(messages[0]["content"].encode("utf-8")).hexdigest()
                    == SYSTEM_PROMPT_SHA256,
                    "provider_messages_invalid",
                )
                summary = json.loads(messages[1]["content"], object_pairs_hook=unique_pairs)
                summary_allowed(summary)
                summary_hash = digest(summary)
                require(
                    summary_hash == checkpoint()["preview_summary_sha256"],
                    "unconfirmed_summary_sent",
                )
                valid = True
            except (Refused, OSError, ValueError, TypeError, KeyError, IndexError):
                pass
            proof = json.loads(read(PROVIDER_PROOF))
            proof["requests"] += 1
            proof["all_payloads_whitelisted"] = proof["all_payloads_whitelisted"] and valid
            require(len(proof["records"]) < 8, "provider_request_count_budget")
            proof["records"].append(
                {
                    "payload_sha256": request_hash,
                    "summary_sha256": summary_hash,
                    "whitelisted": valid,
                }
            )
            write(PROVIDER_PROOF, proof)
            response = b'{"error":{"type":"opsark_controlled_unavailable"}}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    with HTTPServer(("127.0.0.1", PROVIDER_PORT), Handler) as server:
        server.timeout = 0.5
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            server.handle_request()


def run_phase(phase, descriptor):
    api = API(descriptor)
    api.boundaries()
    state = checkpoint()
    if "descriptor_sha256" in state:
        require(state["descriptor_sha256"] == digest(descriptor), "checkpoint_scope_changed")
    state["descriptor_sha256"] = digest(descriptor)
    require(phase not in state["phases"], "verified_phase_cannot_replace_original_proof")
    old = set(state["observations"])
    if phase == "ssh-restored":
        require("ssh-unavailable" in state["phases"], "prior_explicit_unavailability_required")
    if phase == "post-restart":
        require(
            "controller_generation" in state
            and controller_generation() != state["controller_generation"],
            "real_controller_restart_required",
        )
    observation = api.fresh(old)
    if phase == "normal":
        require(
            observation["status"] == "complete"
            and not observation["gaps"]
            and observation["raw_records_seen"] == len(observation["events"]) == 20
            and all(
                row["path_class"] == "normal" and row["status"] == 200
                for row in observation["events"]
            ),
            "normal_complete_control_failed",
        )
        require(
            not any(
                row["kind"] in {"web_scan", "web_error_burst", "web_request_anomaly"}
                for row in api.alerts()
            ),
            "normal_traffic_created_scan_or_ratio_alert",
        )
    elif phase == "ssh-unavailable":
        require(
            "burst" in state["phases"]
            and observation["status"] == "unavailable"
            and not observation["events"]
            and observation["gaps"]
            and api.web()["status"] == "unavailable",
            "explicit_web_unavailable_required",
        )
        history(api, state)
    else:
        require("normal" in state["phases"], "normal_control_first")
        degraded(observation)
        detail, metrics = scan_proof(api, observation)
        if phase == "burst":
            state["native_producer_summary_sha256"] = native_proof(descriptor)
            state["stable_alert_metrics"] = metrics
            state["stable_event_ids"] = sorted(row["id"] for row in observation["events"])
            state["scan_alert_id"] = detail["id"]
            state["controller_generation"] = controller_generation()
        else:
            require(
                "burst" in state["phases"]
                and sorted(row["id"] for row in observation["events"]) == state["stable_event_ids"],
                "native_event_deduplication_changed",
            )
            for baseline in state["stable_alert_metrics"]:
                require(baseline in metrics, "original_alert_id_or_counts_changed")
            if phase in {"repeat", "post-restart"}:
                require(
                    metrics == state["stable_alert_metrics"],
                    "same_window_alert_or_notification_growth",
                )
            history(api, state)
        if phase == "repeat":
            remember(state, observation)
            following = api.fresh(set(state["observations"]))
            degraded(following)
            _, next_metrics = scan_proof(api, following)
            require(
                next_metrics == metrics
                and sorted(row["id"] for row in following["events"]) == state["stable_event_ids"],
                "repeated_poll_grew_counts_or_events",
            )
            observation = following
        if phase == "model-503":
            require(not state.get("model_attempted"), "single_explicit_analysis_only")
            provider = api.call("GET", "/api/ai/status")
            require(
                provider["configured"] is True
                and provider["provider_host"] == "127.0.0.1"
                and provider["model_name"] == PROVIDER_MODEL,
                "local_fake_provider_required",
            )
            before = json.loads(read(PROVIDER_PROOF))
            require(before["requests"] == 0, "unused_fake_provider_required")
            preview = api.call(
                "GET", "/api/security/alerts/" + state["scan_alert_id"] + "/analysis-input"
            )
            summary_allowed(preview["input"])
            require(
                preview["provider_host"] == "127.0.0.1" and preview["model_name"] == PROVIDER_MODEL,
                "local_preview_provider_required",
            )
            state["model_attempted"] = True
            state["preview_summary_sha256"] = digest(preview["input"])
            write(CHECKPOINT, state)
            result = api.call(
                "POST",
                "/api/security/alerts/" + state["scan_alert_id"] + "/analyze",
                {
                    "confirm_send": True,
                    "expected_input_digest": preview["input_digest"],
                },
            )
            require(
                result["status"] == "failed" and result["actions_executable"] is False,
                "model_failure_boundary_failed",
            )
            proof = json.loads(read(PROVIDER_PROOF))
            require(
                proof["requests"] == 1
                and proof["all_payloads_whitelisted"] is True
                and proof["records"][0]["summary_sha256"] == state["preview_summary_sha256"],
                "single_whitelisted_provider_request_failed",
            )
            current = api.call("GET", "/api/security/alerts/" + state["scan_alert_id"])
            require(
                current["analysis"] is None and current["analysis_input_hash"] is None,
                "failed_analysis_was_cached",
            )
            remember(state, observation)
            following = api.fresh(set(state["observations"]))
            degraded(following)
            _, next_metrics = scan_proof(api, following)
            require(
                all(row in next_metrics for row in state["stable_alert_metrics"]),
                "model_failure_changed_observation_counts",
            )
            observation = following
    remember(state, observation)
    state["phases"][phase] = {
        "observation_id": observation["id"],
        "observation_sha256": digest(observation),
    }
    write(CHECKPOINT, state)
    alerts = api.alerts()
    return {
        "phase": phase,
        "verified": True,
        "observation_status": observation["status"],
        "raw_records_seen": observation["raw_records_seen"],
        "retained_events": len(observation["events"]),
        "web_alert_count": len(alerts),
        "notification_count": sum(row["notification_count"] for row in alerts),
        "scan_unique_event_count": sum(
            row["unique_event_count"] for row in alerts if row["kind"] == "web_scan"
        ),
        "read_only": True,
        "business_recovery_claimed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--serve-provider", action="store_true")
    parser.add_argument(
        "phase",
        nargs="?",
        choices=(
            "normal",
            "burst",
            "repeat",
            "post-restart",
            "ssh-unavailable",
            "ssh-restored",
            "prepare-provider",
            "model-503",
        ),
    )
    args = parser.parse_args()
    try:
        descriptor = context(args.descriptor)
        if args.serve_provider:
            require(args.phase is None, "provider_only_mode_required")
            serve_provider()
            return 0
        require(args.phase is not None, "explicit_phase_required")
        proof = (
            prepare_provider()
            if args.phase == "prepare-provider"
            else run_phase(args.phase, descriptor)
        )
        print(json.dumps(proof, sort_keys=True))
    except Refused as error:
        code = str(error)
        if re.fullmatch(r"[a-z_]{1,80}", code) is None:
            code = "controller_acceptance_refused"
        print(json.dumps({"verified": False, "error": code}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, http.client.HTTPException):
        print(json.dumps({"verified": False, "error": "controller_acceptance_refused"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
