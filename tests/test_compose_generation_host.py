"""Verify the target-only Compose generation projection and authenticated socket scope."""

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from deploy.readonly import compose_generation as helper

SCOPE = (
    b'{"compose_project":"synthetic-lab","container_name":"synthetic.web",'
    b'"schema_version":1,"service":"web"}\n'
)
KEY = bytes(range(32))
DAEMON = (1, 2, "1ad3b5b6-7e07-4fc7-a2f3-dc16a823dba4", 3, 4)


def engine_row(**override):
    return {
        "Names": ["/synthetic.web"],
        "Id": "a" * 64,
        "ImageID": "sha256:" + "b" * 64,
        "Image": "mutable-tag",
        "Command": "synthetic-private-command",
        "Labels": {
            helper.LABEL_PROJECT: "synthetic-lab",
            helper.LABEL_SERVICE: "web",
            helper.LABEL_CONFIG: "c" * 64,
            helper.LABEL_VERSION: "v2.20.3",
            "unrelated": "synthetic-private-label",
        },
        **override,
    }


def test_only_filtered_list_and_closed_tokens():
    calls = []

    def get(path):
        calls.append(path)
        return [engine_row()], DAEMON

    found = helper.collect(SCOPE, KEY, get)
    assert len(calls) == 2 and calls[0] == calls[1]
    url = urlsplit(calls[0])
    assert url.netloc == "" and url.path == "/v1.44/containers/json"
    query = parse_qs(url.query)
    assert query.keys() == {"all", "filters"} and query["all"] == ["1"]
    assert json.loads(query["filters"][0]) == {
        "name": [r"^/synthetic\.web$"],
        "label": ["com.docker.compose.project=synthetic-lab", "com.docker.compose.service=web"],
    }
    assert found["scope_digest"] == helper.digest(SCOPE)
    assert found["status"] == "observed" and found["reason"] is None
    assert all(
        helper.HEX.fullmatch(found[key])
        for key in ("binding", "container", "image", "configuration", "compose_version")
    )
    raw = helper.canonical(found)
    for secret in (
        KEY,
        b"synthetic",
        b"mutable-tag",
        b"sha256:",
        b"v2.20.3",
        b"a" * 64,
        b"c" * 64,
    ):
        assert secret not in raw


def test_equality_is_bound_to_key_daemon_and_scope():
    def get(path, image="b", daemon=DAEMON):
        assert path.startswith("/v1.44/containers/json?")
        return [engine_row(ImageID="sha256:" + image * 64)], daemon

    original = helper.collect(SCOPE, KEY, get)
    assert helper.collect(SCOPE, KEY, get) == original
    rotated = helper.collect(SCOPE, bytes(reversed(KEY)), get)
    assert rotated["binding"] != original["binding"]
    restarted = helper.collect(SCOPE, KEY, lambda p: get(p, daemon=(*DAEMON[:-1], 5)))
    assert restarted["binding"] != original["binding"]
    changed = helper.collect(SCOPE, KEY, lambda p: get(p, image="d"))
    assert changed["binding"] == original["binding"]
    assert changed["image"] != original["image"]
    assert changed["container"] == original["container"]


@pytest.mark.parametrize("version", ["", "1.29.2", "2.40.1-rc.1", "3.1.0"])
def test_unsupported_compose_config_is_unavailable_with_engine_evidence(version):
    row = engine_row()
    row["Labels"][helper.LABEL_VERSION] = version
    found = helper.collect(SCOPE, KEY, lambda _: ([row], DAEMON))
    assert found["status"] == "observed" and found["container"] and found["image"]
    assert found["configuration"] is None and found["compose_version"] is None


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [engine_row(), engine_row()],
        [engine_row(Names=["/syntheticXweb"])],
        [engine_row(ImageID="mutable-tag")],
        [engine_row(Labels={helper.LABEL_PROJECT: "synthetic-lab", helper.LABEL_SERVICE: "other"})],
        [engine_row(Labels={helper.LABEL_PROJECT: "other", helper.LABEL_SERVICE: "web"})],
    ],
)
def test_rejects_partial_ambiguous_or_out_of_scope_rows(rows):
    with pytest.raises(helper.Refused, match="^metadata_invalid$"):
        helper.collect(SCOPE, KEY, lambda _: (rows, DAEMON))


def test_rejects_interrupted_generation_and_noncanonical_scope():
    source = iter([([engine_row()], DAEMON), ([engine_row(Id="d" * 64)], DAEMON)])
    with pytest.raises(helper.Refused, match="^evidence_changed$"):
        helper.collect(SCOPE, KEY, lambda _: next(source))
    with pytest.raises(helper.Refused, match="^scope_invalid$"):
        helper.checked_scope(SCOPE.rstrip())
    with pytest.raises(helper.Refused, match="^scope_invalid$"):
        helper.checked_scope(SCOPE.replace(b'"service":', b'"service":"web","service":'))


def test_local_receipt_has_closed_refusal_for_untrusted_or_changed_input(monkeypatch):
    monkeypatch.setattr(helper.sys, "platform", "linux")
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0, raising=False)
    sequence = iter([(SCOPE, (1,)), (KEY, (2,)), (SCOPE, (1,)), (KEY, (3,))])
    monkeypatch.setattr(helper, "read_private", lambda *_: next(sequence))
    monkeypatch.setattr(helper, "endpoint_identity", lambda: DAEMON[:2])
    monkeypatch.setattr(helper, "docker_get", lambda *_: ([engine_row()], DAEMON))
    assert helper.local_projection(["synthetic-argument"]) == helper.unavailable("scope_invalid")
    assert helper.local_projection([]) == helper.unavailable("evidence_changed")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX peer credentials")
@pytest.mark.parametrize("invalid", ["", "short", "duplicate-length"])
def test_native_unix_http_framing_and_peer(tmp_path, monkeypatch, invalid):
    raw = helper.canonical([engine_row()])
    path = tmp_path / "owned.sock"
    monkeypatch.setattr(helper, "SOCKET", path)
    monkeypatch.setattr(helper, "trusted_parents", lambda *_: None)
    request = []

    def witness(peer, _):
        assert peer.family == socket.AF_UNIX
        pid, uid, gid = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert (pid, uid, gid) == (os.getpid(), os.geteuid(), os.getegid())
        return DAEMON[2:]

    monkeypatch.setattr(helper, "daemon_witness", witness)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        path.chmod(0o660)
        if os.geteuid() != 0:
            monkeypatch.setattr(helper, "endpoint_identity", lambda: DAEMON[:2])
        server.listen(1)

        def serve():
            conn, _ = server.accept()
            with conn, conn.makefile("rb") as reader:
                request.append(reader.readline(2048))
                while reader.readline(2048) != b"\r\n":
                    pass
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(raw) + (1 if invalid == "short" else 0)).encode("ascii")
                    + b"\r\n"
                )
                if invalid == "duplicate-length":
                    response += b"Content-Length: 1\r\n"
                conn.sendall(response + b"Connection: close\r\n\r\n" + raw)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        route = helper.list_path(helper.checked_scope(SCOPE))
        endpoint = helper.endpoint_identity()
        if invalid:
            with pytest.raises(helper.Refused):
                helper.docker_get(route, endpoint, time.monotonic() + 4)
        else:
            decoded, actual = helper.docker_get(route, endpoint, time.monotonic() + 4)
            assert decoded == [engine_row()] and actual == (*endpoint, *DAEMON[2:])
        worker.join(4)
        assert not worker.is_alive() and request == [f"GET {route} HTTP/1.1\r\n".encode()]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX peer credentials")
def test_native_unix_peer_rejects_an_unrelated_process():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right, pytest.raises(helper.Refused, match="^collection_unavailable$"):
        helper.daemon_witness(left, time.monotonic() + 2)


@pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="actual Linux root-owned scope metadata",
)
def test_native_scope_and_key_permissions_are_exact():
    with tempfile.TemporaryDirectory(prefix="opsark-compose-generation-", dir="/run") as folder:
        root = Path(folder)
        key = root / "owned"
        key.write_bytes(KEY)
        key.chmod(0o600)
        assert helper.read_private(key, 32)[0] == KEY
        alias = root / "alias"
        alias.symlink_to(key)
        with pytest.raises(helper.Refused, match="^scope_unavailable$"):
            helper.read_private(alias, 32)
        alias.unlink()
        alias.hardlink_to(key)
        with pytest.raises(helper.Refused, match="^scope_unavailable$"):
            helper.read_private(key, 32)
        alias.unlink()
        key.chmod(0o640)
        with pytest.raises(helper.Refused, match="^scope_unavailable$"):
            helper.read_private(key, 32)
