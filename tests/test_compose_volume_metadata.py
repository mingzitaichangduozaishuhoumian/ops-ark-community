"""Check the exact read-only Docker query and closed named-volume projection."""

import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

PATH = Path(__file__).resolve().parents[1] / "deploy/readonly/compose_volume_metadata.py"
SPEC = importlib.util.spec_from_file_location("compose_volume_metadata_host", PATH)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
PROJECT = "synthetic-lab"
SCOPE = b'{"compose_project":"synthetic-lab","schema_version":1}\n'
ENGINE = b'{"id":"synthetic-daemon","os":"linux","security":["name=seccomp"]}\n'
FIRST = "a" * 64
SECOND = "b" * 64
THIRD = "c" * 64
PRIVATE_VOLUME = "DO-NOT-EXPORT-PRIVATE-volume"
PRIVATE_SERVICE = "DO-NOT-EXPORT-PRIVATE-service"


def blob(*rows):
    return b"".join(helper.canonical(row) for row in rows)


def container(identifier, service, state="running"):
    return {"id": identifier, "state": state, "project": PROJECT, "service": service}


def volume(name, label="synthetic-volume"):
    return {"name": name, "driver": "local", "scope": "local", "project": PROJECT, "volume": label}


class Source:
    def __init__(self):
        web = container(FIRST, PRIVATE_SERVICE)
        web_replica = container(SECOND, PRIVATE_SERVICE, "exited")
        worker = container(THIRD, "worker")
        self.calls = []
        self.rows = {
            helper.DOCKER + ("info", "--format", helper.ENGINE): ENGINE,
            helper.arguments(PROJECT): blob(web, web_replica, worker),
            helper.volume_arguments(PROJECT): blob(
                volume(PRIVATE_VOLUME), volume("one"), volume("idle")
            ),
            helper.arguments(PROJECT, volume=PRIVATE_VOLUME): blob(web, web_replica, worker),
            helper.arguments(PROJECT, volume="one"): blob(web_replica, web),
            helper.arguments(PROJECT, volume="idle"): b"",
        }
        self.changes = {}

    def __call__(self, command):
        self.calls.append(command)
        if self.calls.count(command) == 2 and command in self.changes:
            return self.changes[command]
        return self.rows[command]


def test_shared_distinct_services_aliases_and_digest_do_not_expose_local_fields():
    source = Source()
    data = helper.collect(SCOPE, source)
    assert data["status"] == "observed" and data["reason"] is None
    assert data["observed_containers"] == 3
    assert data["coverage"] == "compose_labeled_local_named_volumes"
    assert data["mount_mode"] == "unknown" and data["model_calls"] == 0
    assert data["actions_enabled"] is False and data["scope_digest"] == helper.digest(SCOPE)
    by_type = {row["sharing"]: row for row in data["volumes"]}
    assert set(by_type) == {"shared_across_services", "one_service"}
    single = by_type["one_service"]["services"][0]
    assert (
        single["container_count"] == 2 and single in by_type["shared_across_services"]["services"]
    )
    assert sorted(s["container_count"] for s in by_type["shared_across_services"]["services"]) == [
        1,
        2,
    ]
    assert all(len(row["volume_ref"]) == 32 for row in data["volumes"])
    serialized = helper.canonical(data)
    for item in (
        PRIVATE_VOLUME,
        PRIVATE_SERVICE,
        FIRST,
        SECOND,
        THIRD,
        PROJECT,
        "synthetic-daemon",
        "worker",
    ):
        assert item.encode() not in serialized
    digest = data.pop("snapshot_digest")
    assert digest == helper.digest(helper.canonical(data))
    later = helper.collect(SCOPE, Source())
    assert digest != later["snapshot_digest"]
    assert not {v["volume_ref"] for v in data["volumes"]}.intersection(
        v["volume_ref"] for v in later["volumes"]
    )


def test_docker_queries_fixed_local_scoped_and_never_inspect_or_print_mounts():
    source = Source()
    helper.collect(SCOPE, source)
    assert len(source.calls) == 12 and all(call[:3] == helper.DOCKER for call in source.calls)
    for call in source.calls:
        joined = " ".join(call)
        assert not any(
            field in joined
            for field in (".Mounts", ".Mountpoint", ".Env", " inspect ", " exec ", " logs ")
        )
        if call[3] != "info":
            assert f"label=com.docker.compose.project={PROJECT}" in call
        assert call.count("driver=local") == int(call[3] == "volume")
    with pytest.raises(helper.Refused, match="metadata_invalid"):
        helper.arguments(PROJECT, volume="/host/path")
    with pytest.raises(helper.Refused, match="scope_invalid"):
        helper.arguments("--some-option")


@pytest.mark.parametrize(
    "fields",
    [
        {"driver": "synthetic-plugin"},
        {"scope": "global"},
        {"scope": ""},
        {"driver": "LOCAL"},
    ],
)
def test_driver_or_scope_outside_local_refuses_before_any_attachment_query(monkeypatch, fields):
    monkeypatch.setattr(helper.sys, "platform", "linux")
    source = Source()
    source.rows[helper.volume_arguments(PROJECT)] = blob(
        volume(PRIVATE_VOLUME), volume("other") | fields
    )
    monkeypatch.setattr(helper, "read_scope", lambda _: (SCOPE, "unchanged"))
    monkeypatch.setattr(helper, "run_docker", lambda argv, _: source(argv))

    result = helper.local_projection([])

    assert result == helper.result(reason="metadata_invalid")
    assert len(source.calls) == 3
    assert not any(arg.startswith("volume=") for call in source.calls for arg in call)


@pytest.mark.parametrize("kind", ["containers", "attachment", "volume", "engine"])
def test_drift_refuses_complete_observation(kind):
    source = Source()
    if kind == "containers":
        source.changes[helper.arguments(PROJECT)] = blob(container("d" * 64, PRIVATE_SERVICE))
    elif kind == "attachment":
        source.changes[helper.arguments(PROJECT, volume="one")] = b""
    elif kind == "volume":
        source.changes[helper.volume_arguments(PROJECT)] = blob(volume("else"))
        source.rows[helper.arguments(PROJECT, volume="else")] = b""
    else:
        source.changes[helper.DOCKER + ("info", "--format", helper.ENGINE)] = ENGINE.replace(
            b"daemon", b"changed"
        )
    with pytest.raises(helper.Refused, match="evidence_changed"):
        helper.collect(SCOPE, source)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":true,"compose_project":"synthetic-lab"}',
        b'{"schema_version":1,"compose_project":"synthetic-lab","path":"/somewhere"}',
        b'{"schema_version":1,"compose_project":"a","compose_project":"b"}',
        b'{"schema_version":1,"compose_project":"a/b"}',
        b'{"schema_version":1,"compose_project":"synthetic-lab"}\n',
    ],
)
def test_refuses_invalid_scope_before_docker(raw):
    source = Source()
    with pytest.raises(helper.Refused, match="scope_invalid"):
        helper.collect(raw, source)
    assert source.calls == []


@pytest.mark.parametrize(
    "invalid",
    [
        blob(container(FIRST, "web") | {"env": "synthetic-private"}),
        blob(container(FIRST, "web"), container(FIRST, "web")),
        blob(container(FIRST, "web") | {"project": "other"}),
        blob(container(FIRST, "web") | {"service": "/non-name"}),
        blob(container(FIRST, "web"))[:-1],
    ],
)
def test_strict_container_input_refuses_unknown_or_partial_rows(invalid):
    with pytest.raises(helper.Refused, match="metadata_invalid"):
        helper.containers(invalid, PROJECT)


def test_counts_are_bounded_and_unsupported_metadata_is_not_returned():
    with pytest.raises(helper.Refused, match="metadata_limit"):
        helper.volumes(blob(*(volume(f"volume{i}") for i in range(17))), PROJECT)
    with pytest.raises(helper.Refused, match="metadata_limit"):
        helper.containers(blob(*(container(f"{i:064x}", "web") for i in range(33))), PROJECT)
    with pytest.raises(helper.Refused, match="metadata_invalid"):
        helper.volumes(blob(volume(PRIVATE_VOLUME) | {"volume": ""}), PROJECT)
    with pytest.raises(helper.Refused, match="collection_unavailable"):
        helper.engine(ENGINE.replace(b"name=seccomp", b"name=rootless"))


def test_observed_empty_does_not_claim_mount_mode_or_full_coverage():
    source = Source()
    source.rows[helper.arguments(PROJECT)] = source.rows[helper.volume_arguments(PROJECT)] = b""
    data = helper.collect(SCOPE, source)
    assert (
        data["status"] == "observed" and data["volumes"] == [] and data["observed_containers"] == 0
    )
    assert data["mount_mode"] == "unknown"
    assert data["coverage"] == "compose_labeled_local_named_volumes"


def test_fixed_error_projection_has_no_edges_or_exception_material(monkeypatch):
    monkeypatch.setattr(helper.sys, "platform", "linux")
    canary = "synthetic-private-error"
    with (
        patch.object(helper, "read_scope", return_value=(SCOPE, "identity")),
        patch.object(helper, "run_docker", side_effect=OSError(canary)),
    ):
        data = helper.local_projection([])
    assert data == helper.result(reason="collection_unavailable")
    assert canary not in json.dumps(data) and data["volumes"] == [] and data["scope_digest"] is None
    with patch.object(helper, "read_scope") as check:
        assert helper.local_projection(["some-project"]) == helper.result(reason="scope_invalid")
        check.assert_not_called()


def test_scope_file_replacement_drops_complete_candidate(monkeypatch):
    monkeypatch.setattr(helper.sys, "platform", "linux")
    with (
        patch.object(helper, "read_scope", side_effect=[(SCOPE, "a"), (SCOPE, "b")]),
        patch.object(helper, "run_docker", side_effect=lambda args, _: source(args)),
    ):
        source = Source()
        assert helper.local_projection([]) == helper.result(reason="evidence_changed")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux pipe selectors and fixed helper scope")
@pytest.mark.parametrize(
    ("script", "reason"),
    [
        ("import time; time.sleep(1)", "collection_timeout"),
        ("import os; os.write(2, b'synthetic private error')", "collection_unavailable"),
        ("import os; os.write(1, b'x' * 15000)", "metadata_limit"),
    ],
)
def test_native_pipe_bounds_stop_exact_child(script, reason):
    argv = (os.path.realpath(sys.executable), "-I", "-B", "-c", script)
    with pytest.raises(helper.Refused, match=reason):
        helper.run_docker(argv, time.monotonic() + 0.4)
