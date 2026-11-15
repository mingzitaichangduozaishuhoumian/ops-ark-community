"""Root activation cannot turn a stale or uncertain preview into another restart."""

import copy
import hashlib
import json
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, NOW, load_module, prepare
from test_patch_agent import remote as remote

CTX = "d" * 64
BOOT = "12345678-1234-1234-1234-123456789abc"
LIBRARY = "/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1"


@pytest.fixture
def activation_env(remote, monkeypatch):
    e = remote
    core = e.core
    monkeypatch.setattr(core, "lock", lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(core, "native_package_locks", lambda: nullcontext(), raising=False)
    e.policy.update(
        asset_kind="controlled_lab",
        driver_source_digest="1" * 64,
        allowed_packages=["libexpat1"],
        activation={
            "schema_version": 1,
            "enabled": True,
            "allowed_packages": ["libexpat1"],
            "allowed_units": ["dbus.service"],
            "allow_critical_units": ["dbus.service"],
        },
    )
    e.change.update(
        name="libexpat1",
        current_version="2.6.1-2build1",
        candidate_version="2.6.1-2ubuntu0.6",
        fixed_version="2.6.1-2ubuntu0.6",
    )
    e.finding.update(package="libexpat1", fixed_binary_version=e.change["fixed_version"])
    scan = core.read_json(e.path / "latest-scan.json")
    scan.update(driver_source_digest="1" * 64, findings=[e.finding])
    core.write_json(e.path / "latest-scan.json", scan)
    mode = core.read_json(e.path / "mode.json")
    mode["policy_digest"] = core.policy_digest(e.policy)
    core.write_json(e.path / "mode.json", mode)
    plan = prepare(e)
    folder = e.path / "jobs" / JOB
    folder.mkdir()
    core.write_json(folder / "plan.json", plan)
    manifest = {
        "schema_version": 1,
        "job_id": JOB,
        "package": "libexpat1",
        "architecture": "amd64",
        "version": e.change["current_version"],
        "paths": [LIBRARY],
    }
    core.write_json(folder / "runtime-files-before.json", manifest)
    job = {
        "schema_version": 1,
        "job_id": JOB,
        "host_id": e.policy["host_id"],
        "authorization": "automatic",
        "plan_id": plan["plan_id"],
        "plan_digest": plan["plan_digest"],
        "status": "installed_restart_pending",
        "revision": 7,
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "boot_id": BOOT,
        "install_exit_code": 0,
        "runtime_files_before_sha256": core.digest(manifest),
        "verification": {
            "exact_package_version": {"passed": True},
            "vendor_rescan": {"passed": True},
            "health": {"passed": True},
            "fresh_ssh": {"passed": True},
            "runtime": {"status": "complete", "outdated_process_count": 2},
        },
    }
    core.write_json(folder / "job.json", job)
    safety = {
        "schema_version": 1,
        "paused": True,
        "job_id": JOB,
        "reason": "automatic_job_installed_restart_pending",
        "updated_at": NOW.isoformat(),
    }
    core.write_json(e.path / "automatic-state.json", safety)
    e.inventory["packages"] = [
        {
            "name": "libexpat1",
            "architecture": "amd64",
            "installed_version": e.change["candidate_version"],
        }
    ]
    load_module("scan", "scan.py", monkeypatch)
    load_module("recovery", "recovery.py", monkeypatch)
    load_module("transaction_hook", "transaction_hook.py", monkeypatch)
    worker = load_module("worker", "worker.py", monkeypatch)
    module = load_module("activation", "activation.py", monkeypatch)
    real_unit = module._unit_evidence
    real_outdated = module._outdated
    identity = {
        "pid": 58,
        "starttime_ticks": 100,
        "cgroup": "/system.slice/dbus.service",
        "unit": "dbus.service",
        "exe_path": "/usr/bin/dbus-daemon",
        "exe_sha256": "2" * 64,
        "exe_device": 1,
        "exe_inode": 123,
        "disk_device": 1,
        "disk_inode": 123,
        "deleted_package_paths": [LIBRARY],
    }
    unit = {
        "unit": "dbus.service",
        "main_process": identity,
        "control_group": "/system.slice/dbus.service",
        "fragment_path": "/usr/lib/systemd/system/dbus.service",
        "fragment_sha256": "3" * 64,
        "dropins": [],
        "environment_files": [],
        "configuration_digest": "4" * 64,
        "manager_environment_digest": "5" * 64,
        "refuse_manual_start": False,
        "refuse_manual_stop": False,
        "service_type": "dbus",
        "kill_mode": "control-group",
    }
    state = SimpleNamespace(
        unit=unit,
        processes=[identity],
        restarts=[],
        runtime={"status": "complete", "outdated_process_count": 0, "gaps": []},
    )
    monkeypatch.setattr(module, "_unit_evidence", lambda _u: copy.deepcopy(state.unit))
    monkeypatch.setattr(module, "_outdated", lambda _paths: copy.deepcopy(state.processes))
    monkeypatch.setattr(module, "_boot_id", lambda: BOOT)
    monkeypatch.setattr(core, "uptime_ticks", lambda: 1000)
    monkeypatch.setattr(worker, "package_files", lambda _p: [LIBRARY])
    monkeypatch.setattr(worker, "runtime_maps", lambda _paths: copy.deepcopy(state.runtime))
    assessment = {
        "scan_id": "e" * 32,
        "findings": [{**e.finding, "affected": False, "finding_evidence_complete": True}],
        "coverage": {"status": "partial"},
        "gaps": [],
    }
    monkeypatch.setattr(core, "scan_packages", lambda **_kw: copy.deepcopy(assessment))
    monkeypatch.setattr(core, "fresh_ssh_connection", lambda *_a: False)
    monkeypatch.setenv("SUDO_USER", "opsark-repair")

    def restart(unit):
        state.restarts.append(unit)
        records = list((e.path / "activations").glob("*/activation.json"))
        assert len(records) == 1
        durable = json.loads(records[0].read_bytes())
        assert durable["status"] == "restarting" and durable["restart_evidence"]["intent"]
        assert (records[0].parent / "restart-intent.json").is_file()
        state.unit["main_process"] = {
            **state.unit["main_process"],
            "pid": 1221,
            "starttime_ticks": 200,
            "deleted_package_paths": [],
        }
        return {"exit_code": 0, "result_unknown": False}

    monkeypatch.setattr(module, "_restart", restart)
    return SimpleNamespace(
        **vars(e),
        module=module,
        worker=worker,
        state=state,
        job=job,
        folder=folder,
        patch_plan=plan,
        assessment=assessment,
        real_unit=real_unit,
        real_outdated=real_outdated,
    )


def preview(e):
    return e.module.prepare({"job_id": JOB, "mode_revision": 0, "context_digest": CTX}, e.policy)


def submit(e, plan):
    return e.module.submit(
        {
            key: plan[key]
            for key in ("activation_id", "activation_digest", "mode_revision", "context_digest")
        },
        e.policy,
    )


def mode(e, value, revision=0):
    e.core.write_json(
        e.path / "mode.json",
        {
            "mode": value,
            "revision": revision,
            "policy_digest": e.core.policy_digest(e.policy),
            "updated_at": e.core.stamp(),
        },
    )


def original_bytes(e):
    return (e.folder / "job.json").read_bytes(), (e.path / "automatic-state.json").read_bytes()


def test_preview_binds_exact_original_bytes_without_restarting_or_clearing_pause(activation_env):
    e = activation_env
    before = original_bytes(e)
    plan = preview(e)
    assert set(plan) == e.module.PLAN_FIELDS
    assert {r["id"] for r in plan["checks"]} == e.module.REQUIRED_CHECKS
    assert (
        plan["original_job_status"] == "installed_restart_pending"
        and plan["unit"] == "dbus.service"
    )
    assert plan["original_job_sha256"] == hashlib.sha256(before[0]).hexdigest()
    assert plan["original_safety_digest"] == hashlib.sha256(before[1]).hexdigest()
    assert plan["runtime_manifest_sha256"] == e.job["runtime_files_before_sha256"]
    assert plan["activation_digest"] == e.core.digest(
        {k: v for k, v in plan.items() if k != "activation_digest"}
    )
    assert e.state.restarts == [] and original_bytes(e) == before


def test_manual_preview_does_not_authorize_submit(activation_env):
    e = activation_env
    mode(e, "manual")
    plan = preview(e)
    assert plan["prepared_mode"] == "manual"
    with pytest.raises(e.core.Rejected):
        submit(e, plan)
    assert e.state.restarts == []


@pytest.mark.parametrize("value", ["automatic", "assisted_changed"])
def test_mode_change_blocks_old_plan(activation_env, value):
    e = activation_env
    plan = preview(e)
    mode(e, "automatic" if value == "automatic" else "assisted", 1)
    with pytest.raises(e.core.Rejected):
        submit(e, plan)
    assert e.state.restarts == []


@pytest.mark.parametrize(
    "drift",
    [
        "pid",
        "starttime",
        "cgroup",
        "exe",
        "fragment",
        "environment",
        "process_list",
        "package",
        "repository",
        "job",
        "safety",
        "manifest",
        "policy",
    ],
)
def test_changed_approval_context_never_restarts(activation_env, drift):
    e = activation_env
    plan = preview(e)
    if drift == "pid":
        e.state.unit["main_process"]["pid"] += 1
    elif drift == "starttime":
        e.state.processes[0]["starttime_ticks"] += 1
    elif drift == "cgroup":
        e.state.processes[0]["cgroup"] = "/system.slice/other.service"
    elif drift == "exe":
        e.state.unit["main_process"]["exe_sha256"] = "f" * 64
    elif drift == "fragment":
        e.state.unit["fragment_sha256"] = "f" * 64
    elif drift == "environment":
        e.state.unit["manager_environment_digest"] = "f" * 64
    elif drift == "process_list":
        e.state.processes.append({**e.state.processes[0], "pid": 99})
    elif drift == "package":
        e.inventory["packages"][0]["installed_version"] = "99.0"
    elif drift == "repository":
        e.inventory["apt_state_digest"] = "f" * 64
    elif drift == "job":
        e.core.write_json(e.folder / "job.json", e.job | {"revision": 8})
    elif drift == "safety":
        e.core.write_json(e.path / "automatic-state.json", {"paused": False})
    elif drift == "manifest":
        e.core.write_json(e.folder / "runtime-files-before.json", {"paths": []})
    else:
        e.policy["activation"]["enabled"] = False
    with pytest.raises(e.core.Rejected):
        submit(e, plan)
    assert e.state.restarts == []


@pytest.mark.parametrize(
    "unit",
    [
        "ssh.service",
        "sshd.service",
        "systemd-networkd.service",
        "NetworkManager.service",
        "docker.service",
        "containerd.service",
        "DBus.service",
        "reboot.service",
        "poweroff.service",
        "../dbus.service",
        "dbus@one.service",
        "--bad.service",
        "dbus.service;id",
    ],
)
def test_policy_rejects_critical_and_non_literal_unit_names(activation_env, unit):
    e = activation_env
    policy = copy.deepcopy(e.policy)
    policy["activation"]["allowed_units"] = [unit]
    with pytest.raises(e.core.Rejected):
        e.module.validate_policy(policy)


@pytest.mark.parametrize(
    "change", [{"asset_kind": "host"}, {"critical": []}, {"activation": None}, {"schema": True}]
)
def test_dbus_requires_separate_explicit_test_only_permission(activation_env, change):
    e = activation_env
    policy = copy.deepcopy(e.policy)
    if "critical" in change:
        policy["activation"]["allow_critical_units"] = []
    elif "schema" in change:
        policy["activation"]["schema_version"] = True
    else:
        policy.update(change)
    with pytest.raises(e.core.Rejected):
        e.module.validate_policy(policy)
    old = {k: v for k, v in policy.items() if k != "activation"}
    assert e.module.validate_policy(old) is None


def test_all_affected_processes_must_resolve_to_one_explicit_service(activation_env):
    e = activation_env
    e.state.processes.append({**e.state.processes[0], "unit": "other.service", "pid": 99})
    with pytest.raises(e.core.Rejected):
        preview(e)
    assert e.state.restarts == []


def test_original_pending_without_any_current_old_mapping_is_not_restarted(activation_env):
    e = activation_env
    e.state.processes.clear()
    with pytest.raises(e.core.Rejected):
        preview(e)
    assert e.state.restarts == []


@pytest.mark.parametrize(
    "patch_status", ["applying", "unknown", "awaiting_transport_verification", "running_overdue"]
)
def test_other_active_or_uncertain_patch_excludes_activation(activation_env, patch_status):
    e = activation_env
    other = e.path / "jobs" / ("b" * 32)
    other.mkdir()
    e.core.write_json(other / "job.json", {"job_id": other.name, "status": patch_status})
    with pytest.raises(e.core.Rejected):
        preview(e)
    assert e.state.restarts == []


def test_single_durable_worker_and_new_ssh_verify_without_editing_original_ledgers(
    activation_env, monkeypatch
):
    e = activation_env
    before = original_bytes(e)
    plan = preview(e)
    queued = submit(e, plan)
    assert queued["status"] == "queued" and set(queued) == e.module.RECORD_FIELDS
    assert sum(command[1] == "start" for command in e.commands) == 1
    waiting = e.module.run(plan["activation_id"])
    assert (
        waiting["status"] == "awaiting_transport_verification"
        and waiting["verification"]["fresh_ssh"]["passed"] is False
    )
    assert e.module.status(plan["activation_id"], e.policy) == waiting
    mode(e, "manual", 1)
    monkeypatch.setattr(
        e.core, "fresh_ssh_connection", lambda ticks, boot: ticks == 1000 and boot == BOOT
    )
    final = e.module.status(plan["activation_id"], e.policy)
    assert final["status"] == "verified" and final["effective_result"] == "activation_verified"
    assert final["verification"]["fresh_ssh"]["passed"]
    assert final["record_digest"] == e.core.digest(
        {k: v for k, v in final.items() if k != "record_digest"}
    )
    assert original_bytes(e) == before and e.state.restarts == ["dbus.service"]
    assert e.module.run(plan["activation_id"]) == final
    assert submit(e, plan) == final and len(e.commands) == 1


def test_uncertain_service_result_is_latched_and_never_replayed(activation_env, monkeypatch):
    e = activation_env
    plan = preview(e)
    submit(e, plan)

    def uncertain(unit):
        e.state.restarts.append(unit)
        return {"exit_code": None, "result_unknown": True}

    monkeypatch.setattr(e.module, "_restart", uncertain)
    result = e.module.run(plan["activation_id"])
    assert result["status"] == "unknown"
    assert e.module.run(plan["activation_id"]) == result and submit(e, plan) == result
    with pytest.raises(e.core.Rejected):
        preview(e)
    assert e.state.restarts == ["dbus.service"]


def test_unknown_unit_start_ack_retains_id_before_any_possible_restart(activation_env, monkeypatch):
    e = activation_env
    plan = preview(e)

    def missing_ack(*_a, **_kw):
        raise OSError("secret transport body must not be returned")

    monkeypatch.setattr(e.core, "read_command", missing_ack)
    result = submit(e, plan)
    assert result["status"] == "unknown" and "secret" not in json.dumps(result)
    assert e.module.run(plan["activation_id"]) == result and e.state.restarts == []


@pytest.mark.parametrize("target", ["job", "safety"])
def test_external_ledger_change_after_dispatch_is_not_claimed_unchanged(
    activation_env, monkeypatch, target
):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    restart = e.module._restart

    def changed(unit):
        result = restart(unit)
        if target == "job":
            e.core.write_json(e.folder / "job.json", e.job | {"revision": 8})
        else:
            e.core.write_json(
                e.path / "automatic-state.json",
                {
                    "schema_version": 1,
                    "paused": False,
                    "reason": None,
                    "job_id": None,
                    "updated_at": NOW.isoformat(),
                },
            )
        return result

    monkeypatch.setattr(e.module, "_restart", changed)
    result = e.module.run(plan["activation_id"])
    assert result["status"] == "unknown" and result["original_" + target + "_unchanged"] is False
    assert e.state.restarts == ["dbus.service"]


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"paused": True},
        {
            "schema_version": True,
            "paused": True,
            "reason": "automatic_job_installed_restart_pending",
            "job_id": JOB,
            "updated_at": NOW.isoformat(),
        },
        {
            "schema_version": 1,
            "paused": False,
            "reason": None,
            "job_id": None,
            "updated_at": NOW.isoformat(),
        },
        {
            "schema_version": 1,
            "paused": True,
            "reason": "automatic_job_unknown",
            "job_id": JOB,
            "updated_at": NOW.isoformat(),
        },
    ],
)
def test_automatic_parent_needs_valid_already_persisted_matching_pause(activation_env, value):
    e = activation_env
    path = e.path / "automatic-state.json"
    if value is None:
        path.unlink()
    else:
        e.core.write_json(path, value)
    with pytest.raises(e.core.Rejected):
        preview(e)
    assert not path.exists() if value is None else json.loads(path.read_bytes()) == value
    assert not e.state.restarts


def test_assisted_parent_may_bind_absence_without_creating_safety(activation_env):
    e = activation_env
    e.core.write_json(e.folder / "job.json", e.job | {"authorization": "assisted"})
    (e.path / "automatic-state.json").unlink()
    plan = preview(e)
    assert plan["original_safety_present"] is False
    assert not (e.path / "automatic-state.json").exists()


@pytest.mark.parametrize("drift", ["environment", "mode", "policy"])
def test_worker_rechecks_after_durable_restart_intent_before_dispatch(
    activation_env, monkeypatch, drift
):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    update = e.module._update

    def late_change(identifier, status, **fields):
        result = update(identifier, status, **fields)
        if status == "restarting":
            if drift == "environment":
                e.state.unit["configuration_digest"] = "9" * 64
            elif drift == "mode":
                mode(e, "manual", 1)
            else:
                e.policy["activation"]["enabled"] = False
        return result

    monkeypatch.setattr(e.module, "_update", late_change)
    result = e.module.run(plan["activation_id"])
    assert (
        result["status"] == "rejected" and result["effective_result"] == "activation_not_dispatched"
    )
    assert e.state.restarts == []


def test_expiry_before_dispatch_blocks_but_does_not_rewrite_occurrence_time(
    activation_env, monkeypatch
):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=6))
    result = e.module.run(plan["activation_id"])
    assert result["status"] == "rejected" and e.state.restarts == []
    assert (
        result["approved_at"] == NOW.isoformat()
        and result["completed_at"] == (NOW + timedelta(minutes=6)).isoformat()
    )


def test_restart_dispatched_in_time_can_finish_after_plan_expiry(activation_env, monkeypatch):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    restart = e.module._restart

    def slow(unit):
        result = restart(unit)
        monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=6))
        return result

    monkeypatch.setattr(e.module, "_restart", slow)
    waiting = e.module.run(plan["activation_id"])
    assert waiting["status"] == "awaiting_transport_verification"
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    final = e.module.status(plan["activation_id"], e.policy)
    assert final["status"] == "verified" and final["approved_at"] == NOW.isoformat()
    assert final["restart_evidence"]["intent"]["dispatched_at"] == NOW.isoformat()


@pytest.mark.parametrize("failure", ["runtime", "health", "vendor"])
def test_restart_is_not_final_success_when_postchecks_fail(activation_env, failure):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    if failure == "runtime":
        e.state.runtime["outdated_process_count"] = 1
    elif failure == "health":
        e.baseline["passed"] = False
    else:
        e.assessment["findings"][0]["affected"] = True
    waiting = e.module.run(plan["activation_id"])
    if failure == "health":
        # A baseline already bad before dispatch is rejected without a restart.
        assert waiting["status"] == "rejected" and e.state.restarts == []
    else:
        assert waiting["local_result"] == "verification_failed"
        assert e.state.restarts == ["dbus.service"]


def test_corrupt_durable_record_cannot_be_used_as_idle_or_receipt(activation_env):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    path = e.path / "activations" / plan["activation_id"] / "activation.json"
    record = json.loads(path.read_bytes())
    record["status"] = "verified"
    e.core.write_json(path, record)
    with pytest.raises(e.core.Rejected):
        e.module.assert_idle()
    with pytest.raises(e.core.Rejected):
        e.module.status(plan["activation_id"], e.policy)


def test_unit_environment_and_exec_arguments_are_only_hashed(activation_env, monkeypatch, tmp_path):
    e = activation_env
    root = tmp_path / "system"
    root.mkdir()
    fragment = root / "dbus.service"
    fragment.write_text("[Service]\nExecStart=/usr/bin/dbus-daemon --password unit-secret\n")
    props = dict.fromkeys(e.module.UNIT_PROPERTIES, "")
    props.update(
        Id="dbus.service",
        Names="dbus.service",
        LoadState="loaded",
        ActiveState="active",
        SubState="running",
        MainPID="58",
        ControlGroup="/system.slice/dbus.service",
        FragmentPath=str(fragment),
        RefuseManualStart="no",
        RefuseManualStop="no",
        NeedDaemonReload="no",
        Transient="no",
        KillMode="control-group",
        Type="dbus",
        Environment="PASSWORD=environment-secret",
        ExecStart=(
            "{ path=/usr/bin/dbus-daemon ; argv[]=/usr/bin/dbus-daemon "
            "--password execution-secret ; ignore_errors=no ; start_time=[n/a] ; "
            "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        ),
    )
    monkeypatch.setattr(e.module, "UNIT_ROOTS", (root,))
    monkeypatch.setattr(e.module, "_show", lambda _u: copy.deepcopy(props))
    monkeypatch.setattr(
        e.module, "_process", lambda *_a: copy.deepcopy(e.state.unit["main_process"])
    )
    monkeypatch.setattr(e.core, "read_command", lambda *_a, **_k: (0, "PASSWORD=manager-secret"))
    first = e.real_unit("dbus.service")
    serialized = json.dumps(first)
    assert not any(
        secret in serialized
        for secret in ("unit-secret", "environment-secret", "execution-secret", "manager-secret")
    )
    props["ExecStart"] = (
        props["ExecStart"]
        .replace("pid=0", "pid=1221")
        .replace("start_time=[n/a]", "start_time=[Thu 2026-10-29 11:08:54 UTC]")
    )
    assert first["configuration_digest"] == e.real_unit("dbus.service")["configuration_digest"]
    props["Environment"] = "PASSWORD=changed-secret"
    assert first["configuration_digest"] != e.real_unit("dbus.service")["configuration_digest"]
    props["DropInPaths"] = "/etc/systemd/system/dbus.service.d/override.conf"
    with pytest.raises(e.core.Rejected):
        e.real_unit("dbus.service")
    props["DropInPaths"] = ""
    props["EnvironmentFiles"] = "/etc/hidden-secrets"
    with pytest.raises(e.core.Rejected):
        e.real_unit("dbus.service")


def test_systemd_show_all_preserves_empty_required_unit_properties(activation_env, monkeypatch):
    e = activation_env
    calls = []
    properties = dict.fromkeys(e.module.UNIT_PROPERTIES, "")
    properties.update(
        Id="dbus.service",
        LoadState="loaded",
        ActiveState="active",
        SubState="running",
        ExecStart=rendered_exec(),
    )

    def show(args, **_kwargs):
        calls.append(args)
        rows = properties if "--all" in args else {k: v for k, v in properties.items() if v}
        return 0, "\n".join(k + "=" + v for k, v in rows.items())

    monkeypatch.setattr(e.core, "read_command", show)
    value = e.module._show("dbus.service")
    assert set(value) == set(e.module.UNIT_PROPERTIES)
    assert all(value[name] == "" for name in ("EnvironmentFiles", "ExecStop", "ExecStopPost"))
    assert calls[0][:5] == ["/usr/bin/systemctl", "show", "dbus.service", "--all", "--no-pager"]
    del properties["EnvironmentFiles"]
    monkeypatch.setattr(e.module, "_prove_empty_properties", lambda *_a: e.module._reject())
    with pytest.raises(e.core.Rejected):
        e.module._show("dbus.service")


def test_missing_complex_arrays_require_real_typed_empty_values(activation_env, monkeypatch):
    e = activation_env
    calls = []
    properties = dict.fromkeys(e.module.UNIT_PROPERTIES, "")
    properties.update(
        Id="dbus.service",
        LoadState="loaded",
        ActiveState="active",
        SubState="running",
        ExecStart=rendered_exec(),
    )
    for key in e.module.EMPTY_COMPLEX_PROPERTIES:
        properties.pop(key)
    proofs = []

    def proof(unit, missing):
        assert unit == "dbus.service"
        if not missing <= e.module.EMPTY_COMPLEX_PROPERTIES.keys():
            e.module._reject()
        proofs.append(set(missing))

    def read(arguments, **_kwargs):
        calls.append(arguments)
        assert arguments[0] == "/usr/bin/systemctl"
        return 0, "\n".join(k + "=" + v for k, v in properties.items())

    monkeypatch.setattr(e.core, "read_command", read)
    monkeypatch.setattr(e.module, "_prove_empty_properties", proof)
    result = e.module._show("dbus.service")
    assert all(result[key] == "" for key in e.module.EMPTY_COMPLEX_PROPERTIES)
    assert proofs == [set(e.module.EMPTY_COMPLEX_PROPERTIES)] and len(calls) == 1
    monkeypatch.setattr(e.module, "_prove_empty_properties", lambda *_a: e.module._reject())
    with pytest.raises(e.core.Rejected):
        e.module._show("dbus.service")
    monkeypatch.setattr(e.module, "_prove_empty_properties", proof)
    properties.pop("ExecStart")
    with pytest.raises(e.core.Rejected):
        e.module._show("dbus.service")
    assert proofs == [set(e.module.EMPTY_COMPLEX_PROPERTIES)]


@pytest.mark.parametrize(
    "change",
    [
        {"Id": "unexpected.service"},
        {"LoadState": "not-found"},
        {"ActiveState": "inactive"},
        {"SubState": "dead"},
    ],
)
def test_inactive_units_never_attempt_typed_transport(activation_env, monkeypatch, change):
    e = activation_env
    properties = dict.fromkeys(e.module.UNIT_PROPERTIES, "")
    properties.update(
        Id="dbus.service", LoadState="loaded", ActiveState="active", SubState="running"
    )
    properties.update(change)
    for key in e.module.EMPTY_COMPLEX_PROPERTIES:
        properties.pop(key)
    monkeypatch.setattr(
        e.core,
        "read_command",
        lambda *_a, **_k: (0, "\n".join(k + "=" + v for k, v in properties.items())),
    )
    calls = []
    monkeypatch.setattr(e.module, "_prove_empty_properties", lambda *args: calls.append(args))
    with pytest.raises(e.core.Rejected):
        e.module._show("dbus.service")
    assert not calls


def rendered_exec(*, pid=58, started="[n/a]", argv="/usr/bin/dbus-daemon --system"):
    return (
        "{ path=/usr/bin/dbus-daemon ; argv[]="
        + argv
        + " ; ignore_errors=no ; start_time="
        + started
        + " ; stop_time=[n/a] ; pid="
        + str(pid)
        + " ; code=exited ; status=0/0 }"
    )


def test_lifecycle_changes_do_not_change_command_configuration(activation_env):
    e = activation_env
    before = e.module._exec_configuration(rendered_exec())
    after = e.module._exec_configuration(
        rendered_exec(pid=1221, started="[Thu 2026-10-29 11:08:54 UTC]")
    )
    assert before == after
    assert before != e.module._exec_configuration(
        rendered_exec(argv="/usr/bin/dbus-daemon --system --changed")
    )
    assert e.module._manager_environment("A=one\nB=two\n") == e.module._manager_environment(
        "B=two\nA=one\n"
    )
    assert e.module._manager_environment("A=one") != e.module._manager_environment("A=changed")


@pytest.mark.parametrize(
    "value",
    [
        "/usr/bin/dbus-daemon --secret value",
        "{ path=bad ; unknown=config }",
        "{ path=/usr/bin/dbus-daemon ; argv[]=a }",
        rendered_exec() + " trailing",
    ],
)
def test_unknown_command_renderings_fail_closed_without_echo(activation_env, value):
    e = activation_env
    with pytest.raises(e.core.Rejected) as error:
        e.module._exec_configuration(value)
    assert "secret" not in str(error.value) and value not in str(error.value)


def test_native_package_locks_cover_dispatch_and_postchecks(activation_env, monkeypatch):
    from contextlib import contextmanager

    e = activation_env
    held = []

    @contextmanager
    def native():
        held.append(True)
        try:
            yield
        finally:
            held.pop()

    monkeypatch.setattr(e.core, "native_package_locks", native)
    plan = preview(e)
    submit(e, plan)
    restart = e.module._restart
    verify = e.module._verify

    def restart_locked(unit):
        assert held
        return restart(unit)

    def verify_locked(*args):
        assert held
        return verify(*args)

    monkeypatch.setattr(e.module, "_restart", restart_locked)
    monkeypatch.setattr(e.module, "_verify", verify_locked)
    assert e.module.run(plan["activation_id"])["status"] == "awaiting_transport_verification"
    assert held == []


def test_native_lock_contention_never_dispatches(activation_env, monkeypatch):
    from contextlib import contextmanager

    e = activation_env
    plan = preview(e)
    submit(e, plan)

    @contextmanager
    def busy():
        raise e.core.Rejected("Native package manager owns its lock")
        yield

    monkeypatch.setattr(e.core, "native_package_locks", busy)
    result = e.module.run(plan["activation_id"])
    assert result["status"] == "rejected" and not e.state.restarts


def test_worker_exit_race_does_not_promote_or_restart(activation_env, monkeypatch):
    from contextlib import contextmanager

    e = activation_env
    plan = preview(e)
    submit(e, plan)
    waiting = e.module.run(plan["activation_id"])
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)

    @contextmanager
    def busy(*_a, **_kw):
        raise e.core.Rejected("Worker tail still owns exclusion")
        yield

    monkeypatch.setattr(e.core, "lock", busy)
    assert e.module.status(plan["activation_id"], e.policy) == waiting
    assert e.state.restarts == ["dbus.service"]


@pytest.mark.parametrize("drift", ["package", "pid", "environment", "runtime", "health"])
def test_changes_in_fresh_ssh_confirmation_gap_never_become_verified(
    activation_env, monkeypatch, drift
):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    e.module.run(plan["activation_id"])
    if drift == "package":
        e.inventory["apt_state_digest"] = "9" * 64
    elif drift == "pid":
        e.state.unit["main_process"]["starttime_ticks"] += 1
    elif drift == "environment":
        e.state.unit["manager_environment_digest"] = "9" * 64
    elif drift == "runtime":
        e.state.runtime["outdated_process_count"] = 1
    else:
        e.baseline["passed"] = False
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    result = e.module.status(plan["activation_id"], e.policy)
    assert (
        result["status"] == "verification_failed"
        and result["effective_result"] == "activation_confirmation_changed"
    )
    assert e.state.restarts == ["dbus.service"]


def test_known_failed_local_check_can_be_read_on_fresh_ssh_without_restarting(
    activation_env, monkeypatch
):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    e.state.runtime["outdated_process_count"] = 1
    waiting = e.module.run(plan["activation_id"])
    assert waiting["local_result"] == "verification_failed"
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    result = e.module.status(plan["activation_id"], e.policy)
    assert (
        result["status"] == "verification_failed" and result["verification"]["fresh_ssh"]["passed"]
    )
    assert e.state.restarts == ["dbus.service"]


def test_pid_one_old_package_mapping_is_not_silently_omitted(activation_env, monkeypatch, tmp_path):
    e = activation_env
    pid = tmp_path / "1"
    pid.mkdir()
    monkeypatch.setattr(e.module, "PROC", tmp_path)
    monkeypatch.setattr(
        e.module, "_proc_read", lambda *_a: "0000-1000 r--p 0 8:1 1 " + LIBRARY + " (deleted)"
    )
    monkeypatch.setattr(e.module.os, "readlink", lambda _p: "/usr/lib/systemd/systemd")
    with pytest.raises(e.core.Rejected):
        e.real_outdated([str(Path(LIBRARY).resolve())])


@pytest.mark.parametrize(
    "unit,exe",
    [
        ("web.service", "/usr/sbin/sshd"),
        ("dbus.service", "/usr/sbin/sshd"),
        ("web.service", "/usr/lib/openssh/sshd-session"),
        ("dbus.service", "/usr/lib/openssh/sshd-session"),
        ("web.service", "/usr/lib/openssh/sshd-auth"),
        ("dbus.service", "/usr/lib/openssh/sshd-auth"),
        ("web.service", "/usr/bin/dbus-daemon"),
        ("web.service", "/usr/bin/NetworkManager"),
    ],
)
def test_disguised_critical_executable_is_not_a_generic_allowed_service(activation_env, unit, exe):
    assert activation_env.module._hard_critical(unit, exe)


def test_pid_reuse_and_non_system_cgroups_are_rejected(activation_env, monkeypatch, tmp_path):
    e = activation_env
    pid = tmp_path / "58"
    pid.mkdir()
    (pid / "exe").write_bytes(b"fixture")
    monkeypatch.setattr(e.module, "PROC", tmp_path)
    mapping = "0000-1000 r--p 0 8:1 1 " + LIBRARY + " (deleted)"
    monkeypatch.setattr(
        e.module,
        "_proc_read",
        lambda _pid, name, _max: mapping if name == "maps" else "0::/system.slice/dbus.service",
    )
    monkeypatch.setattr(e.module.os, "readlink", lambda _path: "/usr/bin/dbus-daemon")
    monkeypatch.setattr(
        e.module, "_trusted_binary", lambda _p: ("/usr/bin/dbus-daemon", "f" * 64, 1, 1)
    )
    calls = iter([100, 101])
    monkeypatch.setattr(e.module, "_start", lambda _p: next(calls))
    with pytest.raises(e.core.Rejected):
        e.module._process(58, {str(Path(LIBRARY).resolve())})
    monkeypatch.setattr(e.module, "_start", lambda _p: 100)
    monkeypatch.setattr(
        e.module,
        "_proc_read",
        lambda _pid, name, _max: mapping if name == "maps" else "0::/user.slice/session.scope",
    )
    with pytest.raises(e.core.Rejected):
        e.module._process(58, set())


def test_retention_stops_at_limit_without_restart(activation_env, monkeypatch):
    e = activation_env
    plan = preview(e)
    submit(e, plan)
    monkeypatch.setattr(e.module, "LIMIT", 0)
    with pytest.raises(e.core.Rejected):
        e.module.assert_idle()
    assert e.state.restarts == []


def test_unit_is_no_restart_and_not_a_package_or_shell_entrypoint():
    content = (
        Path(__file__).resolve().parents[1] / "deploy/vulnerability/opsark-activation@.service"
    ).read_text()
    assert "Restart=no" in content and "activation.py %i" in content
    assert all(command not in content for command in ("apt-get", "sh -c", "reboot", "worker.py"))
