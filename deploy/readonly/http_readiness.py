#!/usr/bin/python3 -I
"""Compare one enrolled HTTP response locally and emit a bounded status receipt."""

import hashlib
import hmac
import os
import re
import socket
import sys
from typing import BinaryIO

_ACCOUNT = "opsark-readonly"
_RECEIPT = "OPSARK_HTTP_READINESS_V1"
_MAX_BODY_BYTES = 8192
_MAX_HEADER_BYTES = 16_384
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PATH = re.compile(r"/[A-Za-z0-9._~/-]{0,255}")
_STATUS = re.compile(rb"HTTP/(1\.[01]) ([1-5][0-9]{2})(?: [\x20-\x7e\x80-\xff]*)?")
_HEADER = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e\x80-\xff]*)")
_FRAMING_HEADERS = {b"content-length", b"transfer-encoding", b"content-encoding"}


def _arguments(args: list[str]) -> tuple[str, int, str, int, str]:
    if len(args) != 5:
        raise ValueError
    domain, port, path, expected, digest = args
    if (
        len(domain) > 253
        or not all(_LABEL.fullmatch(label) for label in domain.split("."))
        or re.fullmatch(r"[1-9][0-9]{0,4}", port) is None
        or int(port) > 65535
        or _PATH.fullmatch(path) is None
        or "//" in path
        or any(part in {".", ".."} for part in path.split("/"))
        or re.fullmatch(r"2[0-9]{2}", expected) is None
        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
    ):
        raise ValueError
    return domain, int(port), path, int(expected), digest


def _drop_privileges() -> None:
    import pwd

    account = pwd.getpwnam(_ACCOUNT)
    uid, gid = account.pw_uid, account.pw_gid
    if uid == 0 or gid == 0:
        raise ValueError
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    if (
        os.getresuid() != (uid, uid, uid)
        or os.getresgid() != (gid, gid, gid)
        or set(os.getgroups()) - {gid}
    ):
        raise ValueError


def _line(stream: BinaryIO, limit: int) -> bytes:
    line = stream.readline(limit + 1)
    if len(line) > limit or not line.endswith(b"\r\n"):
        raise ValueError
    return line[:-2]


def _headers(stream: BinaryIO) -> dict[bytes, bytes]:
    remaining = _MAX_HEADER_BYTES
    values: dict[bytes, bytes] = {}
    while remaining >= 2:
        line = _line(stream, remaining)
        remaining -= len(line) + 2
        if not line:
            return values
        header = _HEADER.fullmatch(line)
        if header is None:
            raise ValueError
        name, value = header[1].lower(), header[2].strip(b" \t").lower()
        if name in _FRAMING_HEADERS:
            if name in values:
                raise ValueError
            values[name] = value
    raise ValueError


def _exact(stream: BinaryIO, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise ValueError
    return value


def _chunked_body(stream: BinaryIO) -> bytes:
    value = bytearray()
    while True:
        chunk = _line(stream, 10)
        if re.fullmatch(rb"[0-9A-Fa-f]{1,8}", chunk) is None:
            raise ValueError
        size = int(chunk, 16)
        if size == 0:
            if _headers(stream):
                raise ValueError
            return bytes(value)
        if len(value) + size > _MAX_BODY_BYTES:
            raise ValueError
        value.extend(_exact(stream, size))
        if _exact(stream, 2) != b"\r\n":
            raise ValueError


def _compare(stream: BinaryIO, expected: int, digest: str) -> str:
    line = _STATUS.fullmatch(_line(stream, 512))
    if line is None:
        raise ValueError
    status = int(line[2])
    headers = _headers(stream)
    transfer = headers.get(b"transfer-encoding")
    length = headers.get(b"content-length")
    if (
        status < 200
        or (status == 204 and (transfer is not None or length is not None))
        or (
            transfer is not None
            and (line[1] != b"1.1" or transfer != b"chunked" or length is not None)
        )
        or (length is not None and re.fullmatch(rb"[0-9]{1,10}", length) is None)
    ):
        raise ValueError
    if status != expected:
        return f"{status} status_mismatch"
    if headers.get(b"content-encoding", b"identity") != b"identity":
        raise ValueError
    if status == 204:
        body = b""
    elif transfer == b"chunked":
        body = _chunked_body(stream)
    elif length is not None and int(length) <= _MAX_BODY_BYTES:
        body = _exact(stream, int(length))
    else:
        raise ValueError
    # This GET requests connection closure. Extra bytes after the declared
    # message or a stalled close cannot establish an exact response.
    if stream.read(1):
        raise ValueError
    if hmac.compare_digest(hashlib.sha256(body).hexdigest(), digest):
        return f"{status} match"
    return f"{status} body_mismatch"


def _probe(domain: str, port: int, path: str, expected: int, digest: str) -> str:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {domain}\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(("127.0.0.1", port))
        connection.sendall(request)
        with connection.makefile("rb") as response:
            return _compare(response, expected, digest)


def main(args: list[str] | None = None) -> int:
    try:
        probe = _arguments(sys.argv[1:] if args is None else args)
        _drop_privileges()
        result = _probe(*probe)
    except (KeyError, OSError, ValueError):
        result = "inconclusive"
    print(f"{_RECEIPT} {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
