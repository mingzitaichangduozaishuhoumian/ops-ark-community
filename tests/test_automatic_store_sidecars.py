"""SQLite sidecars can vanish during legitimate concurrent commit, unlike the ledger."""

from pathlib import Path

import pytest

from opsark.automatic_store import AutomaticStore
from opsark.patch_store import PatchStore
from opsark.vulnerability_ai_store import VulnerabilityAIStore
from opsark.vulnerability_store import VulnerabilityStore


@pytest.mark.parametrize(
    "store_type", [AutomaticStore, PatchStore, VulnerabilityAIStore, VulnerabilityStore]
)
def test_sidecar_removed_between_observations_is_not_a_store_failure(
    tmp_path, monkeypatch, store_type
):
    store = store_type(tmp_path / "ledger.sqlite3")
    original = Path.lstat
    existed = Path.exists
    transient = Path(str(store.path) + "-journal")
    observations = []

    def metadata(path, *args, **kwargs):
        if path == transient:
            observations.append(path)
            raise FileNotFoundError("SQLite already removed the committed journal")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(Path, "exists", lambda path: True if path == transient else existed(path))
    with store._connection() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    assert observations


@pytest.mark.parametrize(
    "store_type", [AutomaticStore, PatchStore, VulnerabilityAIStore, VulnerabilityStore]
)
def test_disappeared_durable_ledger_is_not_silently_recreated(tmp_path, store_type):
    store = store_type(tmp_path / "ledger.sqlite3")
    store.path.unlink()
    with pytest.raises(ValueError, match="disappeared"), store._connection():
        pytest.fail("Missing durable ledger must not be recreated")
    assert not store.path.exists()
