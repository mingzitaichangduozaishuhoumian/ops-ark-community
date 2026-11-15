import json
from datetime import UTC, datetime

from opsark.models import CheckResult, Collection
from opsark.redaction import MAX_TEXT, redact, sanitize_collection


def test_credentials_headers_and_private_keys_are_removed():
    value = (
        'password=actual-password api_key="my-secret-value"\n'
        "Authorization: Bearer actual-header-secret\n"
        "Cookie: session=actual-cookie-value\n"
        "https://user:actual-url-password@example.com/log?token=actual-query-secret\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nactual-key-material\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "sk-actualprovidersecretvalue\n"
    )
    result = redact(value)
    for secret in (
        "actual-password",
        "my-secret-value",
        "actual-header-secret",
        "actual-cookie-value",
        "actual-url-password",
        "actual-query-secret",
        "actual-key-material",
        "sk-actualprovidersecretvalue",
    ):
        assert secret not in result
    assert "[REDACTED]" in result


def test_json_redaction_preserves_structure():
    original = '{"token":"not-real-token", "Error":"connection refused", "ExitCode":137}'
    document = json.loads(redact(original))
    assert document["token"] == "[REDACTED]"
    assert document["Error"] == "connection refused"
    assert document["ExitCode"] == 137


def test_sanitization_marks_clipped_evidence_and_keeps_original_unmodified():
    source = Collection(
        host_id="test-host",
        source="ssh",
        started_at=datetime.now(UTC),
        checks=[CheckResult(name="log", stdout="x" * (MAX_TEXT + 1), stderr="password=test-pass")],
    )
    clean = sanitize_collection(source)
    assert clean.checks[0].truncated
    assert len(clean.checks[0].stdout) == MAX_TEXT
    assert "test-pass" not in clean.checks[0].stderr
    assert not source.checks[0].truncated


def test_unterminated_key_is_redacted_through_end_of_input():
    assert "private-key-fragment" not in redact(
        "-----BEGIN RSA PRIVATE KEY-----\nprivate-key-fragment"
    )


def test_database_and_non_http_connection_credentials_are_removed():
    for scheme in ("postgresql", "postgresql+psycopg", "redis", "mysql", "amqp"):
        result = redact(
            f"DATABASE_URL={scheme}://demo:database-secret@db.internal/app?token=query-value"
        )
        assert "database-secret" not in result
        assert "query-value" not in result
        assert "demo:" not in result
