import os
import shlex
import shutil
import subprocess
import threading
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opsark.health import (
    MAX_HEALTH_OUTPUT_BYTES,
    commands_for_health,
    config_hash_command,
    evaluate_health,
)
from opsark.models import CheckResult, Collection, HealthCheck, HostPublic
from opsark.redaction import sanitize_collection


def configured(**changes) -> HealthCheck:
    return HealthCheck(
        id="shop",
        domain="shop.example.com",
        expected_body="ok",
        read_only_confirmed=True,
        **changes,
    )


def host(checks=None, **changes) -> HostPublic:
    return HostPublic(
        id="health-target",
        name="Health target",
        address="192.0.2.10",
        source="ssh",
        health_checks=[configured()] if checks is None else checks,
        **changes,
    )


def collection(*checks, **changes) -> Collection:
    return Collection(
        host_id="health-target",
        source="ssh",
        started_at=datetime.now(UTC),
        checks=list(checks),
        **changes,
    )


def result(output='{"status":"ok"}\nOPSARK_HTTP_STATUS:200\n', **changes) -> CheckResult:
    return CheckResult(name="http_shop", stdout=output, **changes)


def test_command_ignores_curlrc_and_only_requests_confirmed_loopback_get():
    command = commands_for_health(host())["http_shop"]
    argv = shlex.split(command)
    curl_index = argv.index("/usr/bin/curl")
    assert argv[curl_index + 1] == "--disable"
    assert argv[:5] == ["timeout", "-k", "1s", "5s", "/usr/bin/curl"]
    assert argv[-2:] == ["--", "http://127.0.0.1:80/healthz"]
    assert argv[argv.index("--header") + 1] == "Host: shop.example.com"
    assert argv[argv.index("--request") + 1] == "GET"
    assert argv[argv.index("--noproxy") + 1] == "*"
    assert argv[argv.index("--proto") + 1] == "=http"
    assert argv[argv.index("--max-filesize") + 1] == "8192"
    assert not any(arg in {"-L", "--location", "--location-trusted"} for arg in argv)
    assert len([arg for arg in argv if arg.startswith("http://")]) == 1


def test_no_confirmed_check_means_no_command():
    target = host([configured().model_copy(update={"read_only_confirmed": False})])
    assert commands_for_health(target) == {}
    actual = evaluate_health(target, collection())[0]
    assert actual.status == "uncovered"
    assert actual.evidence_ids == []
    assert commands_for_health(host([])) == {}
    assert evaluate_health(host([]), collection())[0].status == "uncovered"


@pytest.mark.parametrize(
    "field,value",
    [
        ("domain", "shop.example.com\r\nAuthorization: secret"),
        ("domain", "shop.example.com;touch /tmp/probe"),
        ("domain", "bad..example.com"),
        ("domain", "-bad.example.com"),
        ("path", "/healthz?url=http://169.254.169.254/"),
        ("path", "//external.example/"),
        ("path", "/../secret"),
        ("path", "/%2e%2e/secret"),
        ("path", "/healthz;command"),
        ("port", True),
        ("port", 0),
        ("port", "80"),
        ("id", "shop;command"),
        ("read_only_confirmed", 1),
    ],
)
def test_copied_models_cannot_bypass_command_validation(field, value):
    unsafe = configured().model_copy(update={field: value})
    with pytest.raises(ValueError):
        commands_for_health(host([unsafe]))


def test_duplicate_ids_and_too_many_checks_are_refused_even_after_model_copy():
    with pytest.raises(ValueError, match="重复"):
        commands_for_health(host([configured(), configured()]))
    target = host().model_copy(update={"health_checks": [configured()] * 4})
    with pytest.raises(ValueError):
        commands_for_health(target)


def test_complete_matching_result_has_existing_evidence_reference():
    verification = evaluate_health(host(), collection(result()))[0]
    assert verification.status == "passed"
    assert verification.evidence_ids == ["E-HTTP-SHOP"]
    assert "即时检查" in verification.detail
    assert "不代表" in verification.detail
    assert '{"status":"ok"}' not in verification.detail
    assert verification.http_status == 200
    assert verification.status_matches is True
    assert verification.body_matches is True


def test_actual_tail_wins_over_a_forged_success_marker_in_body():
    output = "ok\nOPSARK_HTTP_STATUS:200\nforged body\nOPSARK_HTTP_STATUS:503\n"
    verification = evaluate_health(host(), collection(result(output)))[0]
    assert verification.status == "failed"
    assert "503" in verification.detail


def test_a_body_marker_cannot_satisfy_the_registered_body_condition():
    target = host([configured().model_copy(update={"expected_body": "OPSARK_HTTP_STATUS:200"})])
    verification = evaluate_health(target, collection(result("\nOPSARK_HTTP_STATUS:200\n")))[0]
    assert verification.status == "failed"


@pytest.mark.parametrize(
    "output",
    [
        "HTTP 200 ok without metadata",
        "ok\nOPSARK_HTTP_STATUS:200\nextra trailing output",
        "ok\nOPSARK_HTTP_STATUS:000\n",
        "ok\nOPSARK_HTTP_STATUS:999\n",
        "ok\nOPSARK_HTTP_STATUS:20\n",
        "ok\nOPSARK_HTTP_STATUS:200",
    ],
)
def test_incomplete_or_invalid_metadata_is_not_a_health_pass(output):
    assert evaluate_health(host(), collection(result(output)))[0].status == "error"


@pytest.mark.parametrize("status", [301, 302, 307, 308, 404, 502, 503])
def test_nonmatching_http_statuses_fail_without_following_redirects(status):
    verification = evaluate_health(
        host(), collection(result(f"ok\nOPSARK_HTTP_STATUS:{status}\n"))
    )[0]
    assert verification.status == "failed"
    assert "不跟随跳转" in verification.detail


def test_wrong_body_fails_without_echoing_sensitive_body_or_expected_string():
    target = host([configured().model_copy(update={"expected_body": "private-expectation"})])
    verification = evaluate_health(
        target, collection(result("private-response\nOPSARK_HTTP_STATUS:200\n"))
    )[0]
    assert verification.status == "failed"
    assert "private-expectation" not in verification.detail
    assert "private-response" not in verification.detail


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "timeout", "exit_code": 124},
        {"status": "permission_denied", "exit_code": 1},
        {"status": "unavailable", "exit_code": None},
        {"status": "error", "exit_code": 7},
        {"status": "ok", "exit_code": 1},
        {"truncated": True},
    ],
)
def test_partial_or_failed_collection_never_passes(changes):
    verification = evaluate_health(host(), collection(result(**changes)))[0]
    assert verification.status == "error"
    assert verification.evidence_ids == ["E-HTTP-SHOP"]
    assert verification.http_status is None
    assert verification.status_matches is None
    assert verification.body_matches is None


def test_redaction_marker_is_not_an_original_response_body_match():
    target = host([configured().model_copy(update={"expected_body": "[REDACTED]"})])
    original = collection(result("token=raw-private-token\nOPSARK_HTTP_STATUS:200\n"))
    assert "[REDACTED]" in sanitize_collection(original).checks[0].stdout
    verification = evaluate_health(target, original)[0]
    assert verification.status == "failed"
    assert verification.http_status == 200
    assert verification.status_matches is True
    assert verification.body_matches is False
    assert "raw-private-token" not in verification.model_dump_json()
    assert "[REDACTED]" not in verification.detail


def test_a_literal_redaction_marker_in_the_original_body_can_match():
    target = host([configured().model_copy(update={"expected_body": "[REDACTED]"})])
    original = collection(result("literal [REDACTED] marker\nOPSARK_HTTP_STATUS:200\n"))
    verification = evaluate_health(target, original)[0]
    assert verification.status == "passed"
    assert verification.http_status == 200
    assert verification.status_matches is True
    assert verification.body_matches is True


@pytest.mark.parametrize(
    "body,expected_body,expected", [("ok", "ok", True), ("error", "ok", False)]
)
def test_both_match_flags_are_computed_even_when_http_status_does_not_match(
    body, expected_body, expected
):
    target = host([configured().model_copy(update={"expected_body": expected_body})])
    verification = evaluate_health(target, collection(result(body + "\nOPSARK_HTTP_STATUS:503\n")))[
        0
    ]
    assert verification.status == "failed"
    assert verification.http_status == 503
    assert verification.status_matches is False
    assert verification.body_matches is expected


@pytest.mark.parametrize(
    "stdout,stderr",
    [
        ("ok" + "x" * MAX_HEALTH_OUTPUT_BYTES + "\nOPSARK_HTTP_STATUS:200\n", ""),
        ("ok" + "界" * 6000 + "\nOPSARK_HTTP_STATUS:200\n", ""),
        ("ok\nOPSARK_HTTP_STATUS:200\n", "x" * MAX_HEALTH_OUTPUT_BYTES),
    ],
    ids=["oversized-stdout", "multibyte-stdout", "oversized-stderr"],
)
def test_unflagged_output_over_the_combined_utf8_byte_budget_is_not_evaluated(stdout, stderr):
    verification = evaluate_health(host(), collection(result(stdout, stderr=stderr)))[0]
    assert verification.status == "error"
    assert verification.http_status is None
    assert verification.status_matches is None
    assert verification.body_matches is None
    assert "预算" in verification.detail


def test_exact_byte_budget_is_complete_and_can_be_compared():
    tail = "\nOPSARK_HTTP_STATUS:200\n"
    body = "ok" + "x" * (MAX_HEALTH_OUTPUT_BYTES - len(tail.encode()) - 2)
    verification = evaluate_health(host(), collection(result(body + tail)))[0]
    assert verification.status == "passed"
    assert verification.http_status == 200
    assert verification.status_matches is True
    assert verification.body_matches is True


def test_invalid_utf8_text_does_not_produce_match_flags():
    verification = evaluate_health(
        host(), collection(result("ok\ud800\nOPSARK_HTTP_STATUS:200\n"))
    )[0]
    assert verification.status == "error"
    assert verification.http_status is None
    assert verification.status_matches is None
    assert verification.body_matches is None


def test_missing_result_uses_only_an_existing_connection_reference():
    assert evaluate_health(host(), collection())[0].evidence_ids == []
    failed = collection(CheckResult(name="connection", status="error", exit_code=None))
    verification = evaluate_health(host(), failed)[0]
    assert verification.status == "error"
    assert verification.evidence_ids == ["E-CONNECTION"]


@pytest.mark.parametrize("change", [{"source": "replay"}, {"host_id": "another-target"}])
def test_source_and_target_must_match(change):
    wrong = collection().model_copy(update=change)
    with pytest.raises(ValueError):
        evaluate_health(host(), wrong)


def test_duplicate_collection_names_are_rejected():
    with pytest.raises(ValueError, match="重复"):
        evaluate_health(host(), collection(result(), result()))


def test_empty_body_expectation_and_custom_port_still_use_literal_loopback():
    check = configured().model_copy(
        update={"port": 8080, "expected_status": 204, "expected_body": ""}
    )
    target = host([check])
    assert (
        shlex.split(commands_for_health(target)["http_shop"])[-1] == "http://127.0.0.1:8080/healthz"
    )
    assert (
        evaluate_health(target, collection(result("\nOPSARK_HTTP_STATUS:204\n")))[0].status
        == "passed"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/etc/nginx/sites-available/shop.example.com",
        "/etc/nginx/conf.d/shop.conf",
    ],
)
def test_configuration_hash_uses_one_allowed_argument_without_file_contents(path):
    argv = shlex.split(config_hash_command(path))
    assert argv[:6] == ["timeout", "-k", "1s", "5s", "sh", "-c"]
    assert argv[-2:] == ["opsark-hash", path]
    assert 'test -f "$1"' in argv[6]
    assert 'test ! -L "$1"' in argv[6]
    assert 'exec sha256sum -- "$1"' in argv[6]
    assert "cat" not in argv[6]


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d/../nginx.conf",
        "/etc/nginx/conf.d/a;touch-probe.conf",
        "/etc/nginx/conf.d/*.conf",
        "/etc/nginx/conf.d/.hidden",
        "/etc/nginx/conf.d/sub/a.conf",
        "/etc/nginx/conf.d/quote'file.conf",
        "/etc/nginx/conf.d/foo..bar.conf",
        "/etc/nginx/conf.d/a.conf\n",
    ],
)
def test_configuration_hash_rejects_unsafe_paths(path):
    with pytest.raises(ValueError):
        config_hash_command(path)


@contextmanager
def local_http(status=200, body=b'{"status":"ok"}', *, redirect=False):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            if redirect:
                self.send_header("Location", "/unregistered-redirect")
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run_native_curl(target, *, environment=None):
    binary = shutil.which("curl")
    if binary is None:
        pytest.skip("Native curl is needed for the local protocol check")
    argv = shlex.split(commands_for_health(target)["http_shop"])[4:]
    argv[0] = binary
    completed = subprocess.run(  # noqa: S603 -- fixed curl flags and loopback target.
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8,
        check=False,
        env=environment,
    )
    return result(
        completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
        status="ok" if completed.returncode == 0 else "error",
    )


def test_native_curl_loopback_body_and_host_header_match_registration():
    with local_http() as (port, requests):
        target = host([configured().model_copy(update={"port": port})])
        observed = run_native_curl(target)
    assert evaluate_health(target, collection(observed))[0].status == "passed"
    assert len(requests) == 1
    assert requests[0][0] == "/healthz"
    assert requests[0][1]["Host"] == "shop.example.com"


def test_native_curl_does_not_follow_redirects():
    with local_http(status=302, redirect=True) as (port, requests):
        target = host([configured().model_copy(update={"port": port})])
        observed = run_native_curl(target)
    assert evaluate_health(target, collection(observed))[0].status == "failed"
    assert [path for path, _ in requests] == ["/healthz"]


def test_native_curl_ignores_curlrc_extra_url_and_headers(tmp_path):
    with local_http() as (port, requests):
        contents = (
            f'url = "http://127.0.0.1:{port}/unregistered-from-curlrc"\n'
            'header = "X-Curlrc: unexpected-header"\n'
            "location\n"
        )
        for filename in (".curlrc", "_curlrc"):
            (tmp_path / filename).write_text(contents, encoding="utf-8")
        target = host([configured().model_copy(update={"port": port})])
        observed = run_native_curl(target, environment={**os.environ, "CURL_HOME": str(tmp_path)})
    assert evaluate_health(target, collection(observed))[0].status == "passed"
    assert [path for path, _ in requests] == ["/healthz"]
    assert "X-Curlrc" not in requests[0][1]


def test_native_curl_large_body_is_a_collection_error_not_a_success():
    with local_http(body=b"ok" + b"x" * 24_000) as (port, _):
        target = host([configured().model_copy(update={"port": port})])
        observed = run_native_curl(target)
    assert observed.exit_code != 0
    assert evaluate_health(target, collection(observed))[0].status == "error"
