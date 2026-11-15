"""Bounded target-side HTTP comparison and fixed, metadata-only output."""

import hashlib
import socketserver
import threading
from io import BytesIO

import pytest
from test_readonly_guard import load_asset

http_readiness = load_asset("http_readiness")

BODY = b"ready-origin-a\n"
DIGEST = hashlib.sha256(BODY).hexdigest()
SECRET = b"Authorization: Bearer fixture-canary-never-emit"


def response(headers: bytes, body: bytes = b"", status: int = 200) -> bytes:
    return f"HTTP/1.1 {status} Fixture\r\n".encode("ascii") + headers + b"\r\n" + body


def content_length(body: bytes) -> bytes:
    return f"Content-Length: {len(body)}\r\n".encode("ascii")


@pytest.mark.parametrize(
    "wire, result",
    [
        (response(content_length(BODY), BODY), "200 match"),
        (response(content_length(BODY + SECRET), BODY + SECRET), "200 body_mismatch"),
        (response(b"Content-Length: 1234\r\n", status=502), "502 status_mismatch"),
        (
            response(b"Content-Length: 1234\r\nContent-Encoding: gzip\r\n", status=502),
            "502 status_mismatch",
        ),
        (response(b"Location: http://external.invalid/\r\n", status=302), "302 status_mismatch"),
        (
            response(b"Transfer-Encoding: chunked\r\n", b"f\r\n" + BODY + b"\r\n0\r\n\r\n"),
            "200 match",
        ),
    ],
)
def test_response_compares_only_the_complete_body_when_status_matches(wire, result):
    stream = BytesIO(wire)
    assert http_readiness._compare(stream, 200, DIGEST) == result


@pytest.mark.parametrize(
    "wire",
    [
        response(b"", BODY),
        response(b"Content-Length: +15\r\n", BODY),
        response(b"Content-Length: 9000\r\n", BODY),
        response(content_length(BODY) + content_length(BODY), BODY),
        response(content_length(BODY + SECRET), BODY),
        response(content_length(BODY), BODY + SECRET),
        response(content_length(BODY) + b"Content-Encoding: gzip\r\n", BODY),
        response(content_length(BODY) + b"Transfer-Encoding: chunked\r\n", BODY),
        response(b"Transfer-Encoding: chunked\r\n", b"f\r\n" + BODY + b"\r\n"),
        response(b"Transfer-Encoding: chunked\r\n", b"f\r\n" + BODY + b"xy0\r\n\r\n"),
        response(b"Transfer-Encoding: chunked\r\n", b"f\r\n" + BODY + b"\r\n0\r\n"),
        response(b"Transfer-Encoding: chunked\r\n", b"2001\r\n"),
        response(b"x-large: " + b"x" * 16_384 + b"\r\n", BODY),
        b"HTTP/1.1 200 Fixture\r\ncontent-length: 15\n\n" + BODY,
    ],
)
def test_invalid_oversize_and_truncated_messages_cannot_establish_readiness(wire):
    with pytest.raises(ValueError):
        http_readiness._compare(BytesIO(wire), 200, DIGEST)


@pytest.mark.parametrize(
    "index,value",
    [
        (0, "host\r\nInjected: 1"),
        (0, "host..example"),
        (1, "65536"),
        (1, "0"),
        (2, "/one//two"),
        (2, "/one/../two"),
        (2, "/one?q=two"),
        (3, "302"),
        (4, DIGEST.upper()),
    ],
)
def test_invalid_registration_is_inconclusive_without_network(index, value, monkeypatch, capsys):
    args = ["shop.example", "8080", "/ready", "200", DIGEST]
    args[index] = value
    monkeypatch.setattr(http_readiness, "_drop_privileges", lambda: pytest.fail("invalid args"))
    assert http_readiness.main(args) == 0
    assert capsys.readouterr() == ("OPSARK_HTTP_READINESS_V1 inconclusive\n", "")


def test_fixed_loopback_get_emits_no_response_body_header_or_hash(monkeypatch, capsys):
    requests = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            request = []
            for line in self.rfile:
                request.append(line)
                if line == b"\r\n":
                    break
            requests.append(b"".join(request))
            body = BODY + SECRET
            self.wfile.write(response(SECRET + b"\r\n" + content_length(body), body))

    monkeypatch.setattr(http_readiness, "_drop_privileges", lambda: None)
    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        args = ["shop.example", str(server.server_address[1]), "/ready", "200", DIGEST]
        assert http_readiness.main(args) == 0
        thread.join(timeout=2)
    assert requests == [
        b"GET /ready HTTP/1.1\r\nHost: shop.example\r\n"
        b"Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ]
    assert capsys.readouterr() == ("OPSARK_HTTP_READINESS_V1 200 body_mismatch\n", "")
