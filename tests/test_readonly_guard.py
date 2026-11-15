"""Server-side policy and resource boundaries; no network or host credentials."""

import importlib.util
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from opsark.collector import commands_for, commands_for_preflight
from opsark.config import HostConfig
from opsark.models import HostPublic

ROOT = Path(__file__).resolve().parents[1]


def load_asset(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "deploy" / "readonly" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_asset("guard")
entry = load_asset("ssh_entry")
exporter = load_asset("export_policy")
COMMAND = "LC_ALL=C timeout -k 1s 5s cat /etc/os-release"
ARGV = ["timeout", "-k", "1s", "5s", "cat", "/etc/os-release"]


def policy(commands=None):
    return json.dumps({"schema_version": 1, "commands": commands or {COMMAND: ARGV}}).encode()


def test_all_current_generated_commands_fit_exact_policy_protocol():
    host = HostConfig(
        public=HostPublic(id="fixture", name="Fixture", address="192.0.2.10", source="ssh"),
        key_file=Path("unused"),
        known_hosts_file=Path("unused"),
    )
    approved = {
        "LC_ALL=C " + text: shlex.split(text)
        for scenario in ("disk", "web_502", "container_restart", "ssh_security")
        for text in commands_for(host, scenario).values()
    }
    approved.update(
        {"LC_ALL=C " + text: shlex.split(text) for text in commands_for_preflight(host).values()}
    )
    parsed = guard.parse_policy(policy(approved))
    assert parsed == approved
    assert "LC_ALL=C id" not in parsed


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"[]",
        b'{"schema_version":1,"schema_version":1,"commands":{}}',
        b'{"schema_version":true,"commands":{}}',
        json.dumps({"schema_version": 1, "commands": {}, "extra": "ignored?"}).encode(),
    ],
)
def test_malformed_duplicate_or_unknown_policy_fails_closed(raw):
    with pytest.raises(guard.PolicyError):
        guard.parse_policy(raw)


@pytest.mark.parametrize(
    "original,argv",
    [
        ("LC_ALL=C id", ["id"]),
        (COMMAND, ["timeout", "-k", "1s", "5s", "rm", "-rf", "/"]),
        (COMMAND, ["timeout", "-k", "1s", "5s", "cat", "/etc/os-release\x00"]),
        (
            "LC_ALL=C timeout -k 1s 50s cat /etc/os-release",
            ["timeout", "-k", "1s", "50s", "cat", "/etc/os-release"],
        ),
    ],
)
def test_unbounded_commands_and_disagreement_fail_closed(original, argv):
    with pytest.raises(guard.PolicyError):
        guard.parse_policy(policy({original: argv}))


def test_policy_size_is_bounded():
    with pytest.raises(guard.PolicyError):
        guard.parse_policy(b" " * (guard.MAX_POLICY_BYTES + 1))


@pytest.mark.parametrize(
    "mode,uid,directory,expected",
    [
        (stat.S_IFREG | 0o600, 0, False, True),
        (stat.S_IFREG | 0o622, 0, False, False),
        (stat.S_IFREG | 0o600, 1000, False, False),
        (stat.S_IFLNK | 0o777, 0, False, False),
        (stat.S_IFDIR | 0o755, 0, True, True),
        (stat.S_IFDIR | 0o775, 0, True, False),
    ],
)
def test_root_ownership_symlink_and_writable_path_metadata(mode, uid, directory, expected):
    metadata = types.SimpleNamespace(st_mode=mode, st_uid=uid)
    assert guard._metadata_ok(metadata, directory=directory) is expected


def test_guard_rejects_arbitrary_shell_options_and_extra_arguments(monkeypatch, capsys):
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(guard, "load_policy", lambda: {COMMAND: ARGV})
    monkeypatch.setattr(guard, "audit", lambda *args: None)
    called = []
    monkeypatch.setattr(guard, "run_bounded", lambda argv: called.append(argv))
    for arguments in ([], ["id"], [COMMAND + "; id"], [COMMAND, "extra"], ["x" * 5000]):
        assert guard.main(arguments) == 126
    assert called == []
    assert "refused" in capsys.readouterr().err


def test_new_preflight_policy_does_not_admit_other_docker_endpoints_or_actions(monkeypatch, capsys):
    host = HostConfig(
        public=HostPublic(id="fixture", name="fixture", address="192.0.2.10", source="ssh"),
        key_file=Path("unused"),
        known_hosts_file=Path("unused"),
    )
    probes = commands_for_preflight(host)
    allowed = {
        "LC_ALL=C " + probes[name]: shlex.split(probes[name])
        for name in ("compose_version", "docker_rootful")
    }
    assert guard.parse_policy(policy(allowed)) == allowed
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(guard, "load_policy", lambda: allowed)
    monkeypatch.setattr(guard, "audit", lambda *_: None)
    called = []
    monkeypatch.setattr(guard, "run_bounded", lambda *_args, **_kwargs: called.append(True))
    for original in allowed:
        for changed in (
            original + " --project-name other",
            original + "; id",
            original.replace("unix:///var/run/docker.sock", "tcp://other.invalid:2375"),
        ):
            assert guard.main([changed]) == 126
    assert (
        guard.main(
            [
                "LC_ALL=C "
                + probes["compose_version"].replace("compose version --short", "compose up")
            ]
        )
        == 126
    )
    assert not called and "refused" in capsys.readouterr().err


def test_nonroot_direct_helper_execution_is_rejected(monkeypatch, capsys):
    monkeypatch.setattr(guard.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(guard, "audit", lambda *args: None)
    assert guard.main([COMMAND]) == 126
    assert "refused" in capsys.readouterr().err


def test_entry_preserves_original_as_one_argument_and_drops_environment(monkeypatch):
    original = "LC_ALL=C timeout -k 1s 5s cat /etc/os-release; rm -rf /"
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", original)
    monkeypatch.setenv("PYTHONPATH", "/untrusted-python-path")
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid")
    monkeypatch.setattr(entry.sys, "argv", ["entry"])
    seen = []
    monkeypatch.setattr(entry.os, "execve", lambda *args: seen.append(args))
    assert entry.main() == 126
    executable, argv, environment = seen[0]
    assert executable == "/usr/bin/sudo"
    assert argv == ["/usr/bin/sudo", "-n", "--", entry.GUARD, original]
    assert "PYTHONPATH" not in environment
    assert "DOCKER_HOST" not in environment


@pytest.mark.parametrize(
    "command,argv", [("", ["entry"]), ("x" * 5000, ["entry"]), (COMMAND, ["entry", "extra"])]
)
def test_entry_rejects_shell_sessions_and_invalid_invocation(monkeypatch, command, argv):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", command)
    monkeypatch.setattr(entry.sys, "argv", argv)
    seen = []
    monkeypatch.setattr(entry.os, "execve", lambda *args: seen.append(args))
    assert entry.main() == 126
    assert not seen


def test_execution_has_sanitized_environment_and_both_streams(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid")
    monkeypatch.setenv("PYTHONPATH", "/untrusted-python-path")
    code, stdout, stderr = guard.run_bounded(
        [
            sys.executable,
            "-I",
            "-c",
            "import os,sys; print(os.getenv('DOCKER_HOST')); "
            "print(os.getenv('PYTHONPATH')); print('stderr-marker',file=sys.stderr)",
        ]
    )
    assert code == 0
    assert stdout == b"None\nNone\n" or stdout == b"None\r\nNone\r\n"
    assert b"stderr-marker" in stderr


def test_output_budget_cannot_be_exceeded_by_chatty_child():
    code, stdout, stderr = guard.run_bounded(
        [
            sys.executable,
            "-I",
            "-c",
            "import os; os.write(1,b'x'*1000000)",
        ]
    )
    assert code == 125
    assert len(stdout) + len(stderr) <= guard.MAX_OUTPUT_BYTES
    assert b"output_limit" in stderr


def test_wall_clock_deadline_stops_child():
    code, _, stderr = guard.run_bounded(
        [
            sys.executable,
            "-I",
            "-c",
            "import time; time.sleep(10)",
        ],
        wall_seconds=0.2,
    )
    assert code == 124
    assert b"timeout" in stderr


@pytest.mark.parametrize("defense_registered", [False, True])
def test_controller_export_preserves_nonroot_registration_and_omits_key_references(
    tmp_path, defense_registered
):
    (tmp_path / "key-reference").write_text("not-a-real-private-key", encoding="utf-8")
    (tmp_path / "known-reference").write_text("known-reference", encoding="utf-8")
    inventory = tmp_path / "inventory.toml"
    action_id = "a" * 32
    endpoint = (
        'address="198.18.241.2"\nport=22423\n' if defense_registered else 'address="192.0.2.10"\n'
    )
    inventory.write_text(
        '[credentials.fixture]\nkey_file="key-reference"\nknown_hosts_file="known-reference"\n'
        '[[hosts]]\nid="fixture"\n'
        + endpoint
        + 'username="opsark-readonly"\ncredential="fixture"\nsite_domain="example.com"\n'
        + (f'ssh_defense_action_ids=["{action_id}"]\n' if defense_registered else ""),
        encoding="utf-8",
    )
    output = tmp_path / "policy.json"
    result = exporter.export_policy(inventory, "fixture", output)
    parsed = guard.parse_policy(output.read_bytes())
    assert result["allowed_commands"] == len(parsed)
    for text in commands_for_preflight(
        HostConfig(
            public=HostPublic(id="fixture", name="fixture", address="192.0.2.10", source="ssh"),
            key_file=tmp_path / "key-reference",
            known_hosts_file=tmp_path / "known-reference",
        )
    ).values():
        assert parsed["LC_ALL=C " + text] == shlex.split(text)
    assert "not-a-real-private-key" not in output.read_text()
    assert "key-reference" not in output.read_text()
    assert "known-reference" not in output.read_text()
    helper = "/usr/local/libexec/opsark-defense/deploy/defense/ssh_fixture.py"
    defense = f"timeout -k 1s 5s /usr/bin/python3 -I -B {helper} --profile private status-readonly "
    defense += f"--action-id {action_id}"
    assert {original: argv for original, argv in parsed.items() if helper in argv} == (
        {"LC_ALL=C " + defense: shlex.split(defense)} if defense_registered else {}
    )
    inventory.write_text(
        inventory.read_text().replace('username="opsark-readonly"', 'username="root"')
    )
    prior = output.read_bytes()
    with pytest.raises(ValueError, match="非 root"):
        exporter.export_policy(inventory, "fixture", output)
    assert output.read_bytes() == prior


def test_busy_slot_refuses_before_running_approved_command(monkeypatch, capsys):
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(guard, "load_policy", lambda: {COMMAND: ARGV})
    monkeypatch.setattr(guard, "audit", lambda *args: None)

    def busy():
        raise guard.BusyError("fixture slot busy")

    monkeypatch.setattr(guard, "execution_lock", busy)
    called = []
    monkeypatch.setattr(guard, "run_bounded", lambda argv: called.append(argv))
    assert guard.main([COMMAND]) == 75
    assert called == []
    assert "no command executed" in capsys.readouterr().err


@pytest.mark.skipif(
    sys.platform != "linux", reason="Actual Linux flock and killed-parent inheritance"
)
def test_child_keeps_execution_lock_after_guard_process_is_killed(tmp_path):
    import fcntl

    lock = tmp_path / "fixture.lock"
    ready = tmp_path / "ready"
    child_code = (
        "from pathlib import Path; import time; "
        f"Path({str(ready)!r}).write_text('ready'); time.sleep(2)"
    )
    outer_code = (
        "import importlib.util,fcntl,sys; "
        "spec=importlib.util.spec_from_file_location('guard',"
        f"{str(ROOT / 'deploy/readonly/guard.py')!r}); "
        "guard=importlib.util.module_from_spec(spec); spec.loader.exec_module(guard); "
        f"lock=open({str(lock)!r},'w'); fcntl.flock(lock,fcntl.LOCK_EX); "
        f"guard.run_bounded([sys.executable,'-I','-c',{child_code!r}],lock_fd=lock.fileno())"
    )
    outer = subprocess.Popen(  # noqa: S603 -- local fixture interpreter and fixed test code.
        [sys.executable, "-I", "-c", outer_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            assert outer.poll() is None
            time.sleep(0.02)
        assert ready.exists()
        outer.kill()
        outer.wait(timeout=2)
        with lock.open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # The bounded child exits itself; its inherited lock then releases.
            deadline = time.monotonic() + 4
            while True:
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
    finally:
        if outer.poll() is None:
            outer.kill()
            outer.wait(timeout=2)


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Actual root-only Linux policy metadata test",
)
def test_actual_policy_symlink_permissions_and_parent_trust(tmp_path):
    # pytest temp ancestry is commonly /tmp (world writable), which must be refused.
    target = tmp_path / "policy.json"
    target.write_bytes(policy())
    target.chmod(0o600)
    with pytest.raises(guard.PolicyError):
        guard.load_policy(target)
