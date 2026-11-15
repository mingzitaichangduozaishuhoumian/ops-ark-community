"""Replay data is a fixed, fictional input source, never a path-based importer."""

import pytest

from opsark.replay import collect_replay, list_samples


def test_catalog_has_distinct_scenarios_and_declared_targets():
    catalog = list_samples()
    assert len(catalog) == 12
    assert len({sample["id"] for sample in catalog}) == len(catalog)
    assert {sample["scenario"] for sample in catalog} == {
        "web_502",
        "disk",
        "container_restart",
        "ssh_security",
    }
    for sample in catalog:
        host, collection = collect_replay(sample["id"])
        assert sample["title"].startswith("回放：")
        assert sample["host_id"] == host.id == collection.host_id
        assert host.source == collection.source == "replay"
        assert collection.started_at.tzinfo is not None
        assert not any("report" in check.name for check in collection.checks)


@pytest.mark.parametrize(
    "sample_id",
    [
        "unknown",
        "../secrets",
        "web-port-mismatch.json",
        "C:/Windows/win.ini",
        "../../web-port-mismatch",
        "",
    ],
)
def test_unknown_or_path_like_input_never_selects_a_file(sample_id):
    with pytest.raises(KeyError):
        collect_replay(sample_id)


def test_each_replay_has_fresh_models_and_read_time():
    host, collection = collect_replay("disk-healthy")
    host.name = "modified externally"
    collection.checks[0].stdout = "replaced outside replay"
    fresh_host, fresh_collection = collect_replay("disk-healthy")
    assert fresh_host.name == "web-demo-01"
    assert "ID=ubuntu" in fresh_collection.checks[0].stdout
    assert fresh_collection.started_at >= collection.started_at
