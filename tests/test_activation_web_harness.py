"""Actual local relay byte/EOF checks and private-controller environment boundaries."""

import os
import socket
import subprocess
import sys
from types import SimpleNamespace

import activation_web_acceptance as web
import pytest

from opsark.config import Settings


def test_rescan_cannot_enable_a_non_web_guest(monkeypatch, tmp_path):
    import activation_guest_acceptance as harness

    monkeypatch.setattr(
        harness, "docker", lambda *_a, **_k: pytest.fail("Docker must not be called")
    )
    with pytest.raises(ValueError, match="Web"):
        harness.run("debian:12", tmp_path, activation_rescan=True)


@pytest.mark.parametrize("length", [1, 196_608])
def test_byte_relay_preserves_binary_and_half_close(monkeypatch, length):
    original = subprocess.Popen
    seen = []
    script = (
        "import sys,struct\nh=struct.Struct('!cII')\n"
        "sys.stdout.buffer.write(b'READY\\n');sys.stdout.buffer.flush()\n"
        "while True:\n"
        " b=sys.stdin.buffer.read(h.size)\n if not b: break\n"
        " k,i,n=h.unpack(b); d=sys.stdin.buffer.read(n)\n"
        " if k in (b'D',b'E'):\n"
        "  sys.stdout.buffer.write(h.pack(b'D' if k==b'D' else b'C',i,len(d))+d)\n"
        "  sys.stdout.buffer.flush()\n"
    )

    def child(argv, **kwargs):
        seen.append((argv, kwargs["env"]))
        return original([sys.executable, "-I", "-c", script], **kwargs)

    monkeypatch.setattr(web.subprocess, "Popen", child)
    monkeypatch.setattr(web.shutil, "which", lambda _: sys.executable)
    monkeypatch.setenv("DOCKER_HOST", "tcp://unapproved:2375")
    payload = (bytes(range(256)) * (length // 256 + 1))[:length]
    with (
        web.ssh_relay("a" * 64) as port,
        socket.create_connection(("127.0.0.1", port), timeout=10) as connection,
    ):
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        output = bytearray()
        while chunk := connection.recv(65536):
            output.extend(chunk)
    assert output == payload
    assert len(seen) == 1
    argv, environment = seen[0]
    assert argv[-4:] == [
        "a" * 64,
        "/usr/bin/python3",
        "-I",
        "/usr/local/libexec/opsark-activation-lab-relay.py",
    ]
    assert argv[argv.index("--user") + 1] == "opsark-repair"
    assert not any(k.startswith("DOCKER_") for k in environment)


def test_controller_uses_production_app_with_only_private_settings(monkeypatch, tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        token="temporary-test-token-" * 3,
        inventory_path=tmp_path / "inventory.toml",
        patch_inventory_path=tmp_path / "patch.json",
    )
    controller = web.Controller(settings, tmp_path)
    seen = {}
    process = SimpleNamespace(
        pid=1234, poll=lambda: None, terminate=lambda: None, wait=lambda **_: 0
    )

    def launch(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return process

    monkeypatch.setattr(web.subprocess, "Popen", launch)
    monkeypatch.setattr(
        controller.client,
        "get",
        lambda _: SimpleNamespace(status_code=200, json=lambda: {"mode_sync_complete": True}),
    )
    monkeypatch.setenv("OPSARK_AI_KEY", "do-not-inherit")
    monkeypatch.setenv("OPSARK_DATA_DIR", "unapproved-data")
    monkeypatch.setenv("OPSARK_OBSERVE_ENABLED", "true")
    monkeypatch.setenv("OPSARK_VULNERABILITY_SCAN_ENABLED", "true")
    try:
        controller.start()
    finally:
        controller.close()
    assert "opsark.main:app" in seen["argv"]
    assert seen["argv"][seen["argv"].index("--host") + 1] == "127.0.0.1"
    environment = seen["env"]
    assert environment["OPSARK_DATA_DIR"] == str(settings.data_dir)
    assert environment["OPSARK_INVENTORY"] == str(settings.inventory_path)
    assert environment["OPSARK_PATCH_INVENTORY"] == str(settings.patch_inventory_path)
    for name in ("OPSARK_AI_KEY", "OPSARK_OBSERVE_ENABLED", "OPSARK_VULNERABILITY_SCAN_ENABLED"):
        assert name not in environment
    assert environment["PYTHONPATH"] == str(web.ROOT / "src")
    assert os.environ["OPSARK_DATA_DIR"] == "unapproved-data"
