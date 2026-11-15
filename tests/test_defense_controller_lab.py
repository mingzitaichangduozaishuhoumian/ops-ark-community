"""Pure/fake controller laboratory tests: no Docker, SSH, model or subprocess."""

import ast
import copy
import hashlib
import inspect
import io
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
import ssh_defense_controller_lab as lab


def command(operation="snapshot", request_id="a" * 32):
    return {
        "schema": "opsark-controller-command/v1",
        "request_id": request_id,
        "operation": operation,
        "fixture_id": "b" * 16,
    }


@pytest.mark.parametrize("operation", sorted(lab.OPERATIONS))
def test_fixed_command_grammar(operation):
    value = command(operation)
    assert lab.checked_command(value) == value


@pytest.mark.parametrize(
    "change",
    [
        {"request_id": "a" * 31},
        {"request_id": True},
        {"fixture_id": "b" * 15},
        {"schema": "other"},
        {"operation": "rm -rf"},
        {"operation": ["snapshot"]},
        {"address": "198.18.241.3"},
        {"argv": ["/bin/sh"]},
        {"ttl_ms": 60001},
    ],
)
def test_unknown_arguments_and_types_refused(change):
    with pytest.raises(lab.native.LabError):
        lab.checked_command(command() | change)


def test_new_start_retains_old_exact_security_profile_and_old_timeout():
    old = ast.parse(textwrap.dedent(inspect.getsource(lab.native.Network.start)))
    new_source = textwrap.dedent(inspect.getsource(lab.ControllerNetwork.start))
    new = ast.parse(new_source.replace("LIFETIME_SECONDS", "CONTAINER_SECONDS"))
    assert ast.dump(old) == ast.dump(new)
    assert lab.native.CONTAINER_SECONDS == 180
    assert lab.LIFETIME_SECONDS == 600 and lab.WORK_SECONDS + lab.CLEANUP_SECONDS == 600
    original = lab.native.SELF
    with lab.bound_self():
        assert lab.native.SELF == lab.SELF
        assert lab.native.CONTAINER_SECONDS == 180
    assert original == lab.native.SELF


def test_five_core_sources_remain_frozen():
    root = Path(__file__).resolve().parents[1]
    for name, expected in lab.CORE_SHA256.items():
        assert (
            hashlib.sha256((root / "deploy" / "defense" / name).read_bytes()).hexdigest()
            == expected
        )


@pytest.fixture
def wrapper(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    monkeypatch.setattr(lab.native, "internal_modules", lambda: None)
    monkeypatch.setattr(lab.native, "fixture_case", lambda: lab.native.SOCKET_CASE)
    monkeypatch.setattr(lab.native, "diagnostic_step", lambda *_args, **_kw: None)
    monkeypatch.setattr(lab.native, "FAULT_ROOT", tmp_path)
    monkeypatch.setattr(lab.native, "owned_create", lambda path, value: path.write_bytes(value))
    monkeypatch.setattr(lab.native, "owned_read", lambda path, _limit: path.read_bytes())
    monkeypatch.setattr(lab.native, "validate_reply", lambda value, _request: value)
    sent, closed = [], []

    def run(*argv, **kwargs):
        sent.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=state["stdout"], stderr=b"")

    monkeypatch.setattr(lab.native, "run", run)
    monkeypatch.setattr(
        lab.native, "request_socket_interruption", lambda *args: closed.append(args)
    )
    output, error = io.BytesIO(), io.BytesIO()
    streams = SimpleNamespace(
        stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error)
    )
    monkeypatch.setattr(lab, "sys", streams)
    state = {"stdout": b'{"state":"ready"}\n'}

    def invoke(op, body, receipt=None):
        request = {"v": 1, "op": op, "request_id": "a" * 32, "scope_sha256": "b" * 64, "body": body}
        raw = lab.native.canonical(request) + b"\n"
        streams.stdin = SimpleNamespace(buffer=io.BytesIO(raw))
        if receipt is not None:
            state["stdout"] = lab.native.canonical(receipt) + b"\n"
        return lab.controller_control_wrapper()

    return SimpleNamespace(invoke=invoke, sent=sent, closed=closed, output=output, root=tmp_path)


def test_prepare_passes_through_without_any_socket_or_request_marker(wrapper):
    body = {
        "cursor_id": "c" * 32,
        "source_ref": "d" * 32,
        "evidence_sha256": "e" * 64,
        "policy_sha256": "f" * 64,
        "mode": "semi",
        "mode_revision": 2,
        "controller_grant_ref": "1" * 32,
        "root_grant_ref": "2" * 32,
    }
    assert wrapper.invoke("prepare", body) == 0
    assert wrapper.output.getvalue() == b'{"state":"ready"}\n'
    assert not wrapper.closed and not list(wrapper.root.iterdir())
    assert wrapper.sent[0][0] == (
        "/usr/bin/python3",
        "-I",
        "-B",
        lab.native.INSTALLED,
        "--control",
    )


def test_only_active_apply_requests_exact_existing_socket_closure(wrapper):
    receipt = {
        "state": "active",
        "action_id": "c" * 32,
        "manifest_sha256": "d" * 64,
        "cursor_id": "e" * 32,
        "remaining_ms": 59000,
    }
    assert wrapper.invoke("apply", {"manifest_sha256": "d" * 64, "approval": None}, receipt) == 0
    assert len(wrapper.closed) == 1 and wrapper.closed[0][0]["op"] == "apply"
    assert wrapper.closed[0][2] == 59000
    assert (wrapper.root / "controller-apply-request.json").is_file()


def test_rejected_apply_does_not_close_socket_or_save_request(wrapper):
    assert (
        wrapper.invoke(
            "apply", {"manifest_sha256": "d" * 64, "approval": None}, {"state": "rejected"}
        )
        == 0
    )
    assert not wrapper.closed and not list(wrapper.root.iterdir())


def test_original_mailbox_identity_is_immutable(tmp_path, monkeypatch):
    monkeypatch.setattr(lab.native, "require_root", lambda _root: None)
    monkeypatch.setattr(lab, "supervisor_alive", lambda _record: True)
    monkeypatch.setattr(lab, "live_resources", lambda _ready: True)
    monkeypatch.setattr(lab, "read_json", lambda path, limit=8192: json.loads(path.read_text()))
    monkeypatch.setattr(lab, "write_new", lambda path, value: path.write_text(json.dumps(value)))
    (tmp_path / "controller-ready.json").write_text(json.dumps({"fixture_id": "b" * 16}))
    (tmp_path / "supervisor.json").write_text("{}")
    (tmp_path / "controller-commands").mkdir()
    (tmp_path / "controller-results").mkdir()
    rid = "a" * 32
    assert lab.command(tmp_path, "snapshot", rid) == {"request_id": rid, "pending": True}
    assert lab.command(tmp_path, "snapshot", rid)["pending"]
    with pytest.raises(lab.native.LabError):
        lab.command(tmp_path, "stop", rid)
    result = {
        "request_id": rid,
        "operation": "snapshot",
        "command_sha256": lab.native.digest(command()),
        "completed": True,
        "result": {"safe": True},
    }
    (tmp_path / "controller-results" / (rid + ".json")).write_text(json.dumps(result))
    assert lab.command(tmp_path, "snapshot", rid) == result
    # Completed original commands remain readable after the supervisor exits.
    monkeypatch.setattr(lab, "supervisor_alive", lambda _record: False)
    assert lab.command(tmp_path, "snapshot", rid) == result


def test_stimulus_is_claimed_before_first_auth_attempt_and_never_repeated(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(lab, "projection", lambda *_args, **_kw: {"cursor_request_id": "c" * 32})
    monkeypatch.setattr(lab, "write_new", lambda path, value: path.write_text(json.dumps(value)))

    def interrupted_login(*_args, **_kwargs):
        assert (tmp_path / "stimulus.once.json").exists()
        calls.append("attempt")
        raise OSError("synthetic private diagnostic")

    monkeypatch.setattr(lab.native, "login", interrupted_login)
    network = SimpleNamespace(fixture="b" * 16)
    with pytest.raises(OSError):
        lab.process_command(
            command("stimulate"), tmp_path, network, "target", {"candidate": "candidate"}
        )
    with pytest.raises(lab.native.LabError):
        lab.process_command(
            command("stimulate", "d" * 32), tmp_path, network, "target", {"candidate": "candidate"}
        )
    assert calls == ["attempt"]


@pytest.mark.parametrize("state,start,expected", [("S", 2, True), ("Z", 2, False), ("S", 3, False)])
def test_original_supervisor_pid_and_start_ticks_are_checked(monkeypatch, state, start, expected):
    monkeypatch.setattr(
        lab, "process_identity", lambda pid: {"pid": pid, "state": state, "start_ticks": start}
    )
    assert lab.supervisor_alive({"pid": 1234, "start_ticks": 2}) is expected


@pytest.fixture
def resources(tmp_path, monkeypatch):
    fixture, network_id, image = "b" * 16, "c" * 64, "sha256:" + "d" * 64
    name = "opsark-requests-" + fixture
    identifiers = {
        role: str(index) * 64 for index, role in enumerate(("target", *lab.native.ADDRESSES), 1)
    }
    ready = {
        "fixture_id": fixture,
        "network_id": network_id,
        "image_id": image,
        "container_ids": identifiers,
        "workspace": str(tmp_path / "workspace"),
        "stage_root": str(tmp_path),
    }
    rows = {
        network_id: {
            "Id": network_id,
            "Name": name,
            "Driver": "bridge",
            "Internal": True,
            "EnableIPv6": False,
            "IPAM": {"Config": [{"Subnet": lab.native.SUBNET, "Gateway": "198.18.241.1"}]},
            "Labels": {lab.LABEL: fixture},
            "Containers": dict.fromkeys(identifiers.values(), {}),
        }
    }
    for role, identity in identifiers.items():
        target = role == "target"
        argv = (
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                lab.SELF,
                "--internal-target",
                "--image",
                image,
                "--confirm-isolated",
            ]
            if target
            else ["/bin/sleep", "infinity"]
        )
        rows[identity] = {
            "Id": identity,
            "Image": image,
            "State": {"Running": True},
            "Config": {
                "User": "0:0",
                "Labels": {lab.LABEL: fixture},
                "Entrypoint": ["/usr/bin/timeout"],
                "Cmd": ["-k", "2s", "600s", *argv],
            },
            "HostConfig": {
                "NetworkMode": name,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "CapAdd": list(lab.CAPS) if target else [],
                "ReadonlyRootfs": not target,
                "SecurityOpt": [] if target else ["no-new-privileges:true"],
                "PidMode": "",
                "IpcMode": "private",
                "CgroupnsMode": "private",
                "UTSMode": "",
                "UsernsMode": "",
                "Devices": [],
                "DeviceRequests": None,
                "PortBindings": {},
                "PublishAllPorts": False,
                "VolumesFrom": [],
                "PidsLimit": 96,
                "Memory": 192 * 1024**2,
                "MemorySwap": 192 * 1024**2,
                "NanoCpus": 500_000_000,
                "RestartPolicy": {"Name": "no"},
            },
            "NetworkSettings": {
                "Networks": {
                    name: {
                        "NetworkID": network_id,
                        "IPAddress": lab.native.TARGET if target else lab.native.ADDRESSES[role],
                    }
                }
            },
        }
    monkeypatch.setattr(lab, "trusted_directory", lambda *_args, **_kw: None)
    calls = []

    def run(*args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(
            returncode=0, stderr=b"", stdout=json.dumps([rows[args[-1]]]).encode()
        )

    monkeypatch.setattr(lab.native, "run", run)
    return SimpleNamespace(ready=ready, rows=rows, ids=identifiers, calls=calls)


def test_status_rechecks_actual_five_owned_resources(resources):
    assert lab.live_resources(resources.ready)
    assert len(resources.calls) == 5
    assert all(args[-2] == "inspect" for args in resources.calls)


@pytest.mark.parametrize(
    "change",
    [
        "stopped",
        "foreign_ip",
        "unbounded_cpu",
        "wrong_timeout",
        "rootfs",
        "host_pid",
        "extra_endpoint",
    ],
)
def test_resource_status_refuses_stale_or_changed_scope(resources, change):
    rows = resources.rows
    management = rows[resources.ids["management"]]
    name = "opsark-requests-" + resources.ready["fixture_id"]
    if change == "stopped":
        management["State"]["Running"] = False
    elif change == "foreign_ip":
        management["NetworkSettings"]["Networks"][name]["IPAddress"] = "198.18.241.3"
    elif change == "unbounded_cpu":
        management["HostConfig"]["NanoCpus"] = 0
    elif change == "wrong_timeout":
        management["Config"]["Cmd"][2] = "infinity"
    elif change == "rootfs":
        management["HostConfig"]["ReadonlyRootfs"] = False
    elif change == "host_pid":
        management["HostConfig"]["PidMode"] = "host"
    else:
        rows[resources.ready["network_id"]]["Containers"]["f" * 64] = {}
    with pytest.raises(lab.native.LabError):
        lab.live_resources(copy.deepcopy(resources.ready))
