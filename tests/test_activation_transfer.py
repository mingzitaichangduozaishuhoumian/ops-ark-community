"""Offline transport clears both leases and preserves activation evidence in ten stores."""

import sqlite3

from test_store_transfer import make_directory, transfer


def test_patch_and_activation_leases_are_cleared_only_on_manifested_copy(tmp_path):
    source = make_directory(tmp_path / "source")
    path = source / "patches.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE patch_monitor_lease(id INTEGER PRIMARY KEY,owner TEXT,expires_at REAL);"
            "CREATE TABLE service_activation_monitor("
            "id INTEGER PRIMARY KEY,owner TEXT,expires_at TEXT);"
            "CREATE TABLE service_activation_records(host_id TEXT,activation_id TEXT,payload TEXT);"
            "INSERT INTO patch_monitor_lease VALUES(1,'old-patch-owner',99999);"
            "INSERT INTO service_activation_monitor VALUES(1,'old-activation-owner','2099-01-01');"
            "INSERT INTO service_activation_records VALUES('host','original','immutable fixture');"
        )
    path.chmod(0o600)
    original = path.read_bytes()
    snapshot = transfer.snapshot(source, tmp_path / "copy")
    manifest = transfer.clear_monitor_leases(tmp_path / "copy")
    assert manifest["cleared_lease_rows"]["patches.sqlite3"] == 2
    assert path.read_bytes() == original
    with sqlite3.connect(tmp_path / "copy/patches.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM patch_monitor_lease").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM service_activation_monitor").fetchone()[0] == 0
        )
        assert connection.execute("SELECT payload FROM service_activation_records").fetchone()[
            0
        ] == ("immutable fixture")
    assert (
        manifest["databases"]["patches.sqlite3"]["tables"]["service_activation_records"]
        == (snapshot["databases"]["patches.sqlite3"]["tables"]["service_activation_records"])
    )
