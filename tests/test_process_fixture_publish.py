"""Ready/stop/audit JSON must appear complete, without replacing old evidence."""

import json
from threading import Event, Thread

import pytest
from defense_recheck_process_restart import _json


def test_process_handshake_file_is_invisible_until_json_is_complete(tmp_path, monkeypatch):
    path = tmp_path / "ready.json"
    writing, proceed = Event(), Event()
    original_dump = json.dump
    errors = []

    def blocked_dump(value, stream, **kwargs):
        writing.set()
        assert proceed.wait(3)
        return original_dump(value, stream, **kwargs)

    monkeypatch.setattr(json, "dump", blocked_dump)

    def publish():
        try:
            _json(path, {"pid": 123, "ready": True})
        except Exception as error:
            errors.append(type(error).__name__)

    thread = Thread(target=publish)
    thread.start()
    try:
        assert writing.wait(3)
        assert not path.exists()
    finally:
        proceed.set()
        thread.join(3)
    assert not thread.is_alive() and not errors
    assert json.loads(path.read_bytes()) == {"pid": 123, "ready": True}
    assert set(tmp_path.iterdir()) == {path}


def test_process_handshake_never_overwrites_existing_evidence(tmp_path):
    path = tmp_path / "audit.json"
    path.write_bytes(b"preserved original evidence\n")
    with pytest.raises(FileExistsError):
        _json(path, {"changed": True})
    assert path.read_bytes() == b"preserved original evidence\n"
    assert set(tmp_path.iterdir()) == {path}


def test_failed_handshake_serialization_publishes_nothing(tmp_path):
    with pytest.raises(TypeError):
        _json(tmp_path / "ready.json", {"unsupported": object()})
    assert not list(tmp_path.iterdir())
