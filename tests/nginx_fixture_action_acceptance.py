#!/usr/bin/env python3
"""Exercise the approval-bound action and process-loss lookup on real isolated Nginx."""

import argparse
import hashlib
import json
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory

from deploy.nginx import config_snapshot, fixture_action, fixture_context, fixture_runtime
from tests.nginx_fixture_pki import generate_chain_tls

ORIGINAL = b"""server {
    listen 127.0.0.1:18087;
    server_name target.opsark.invalid;
    location = /healthz { default_type text/plain; return 200 "opsark-original"; }
}
"""
CANDIDATE = ORIGINAL.replace(b"opsark-original", b"opsark-candidate")
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def docker(base: list[str], *args: str) -> bytes:
    run = subprocess.run(  # noqa: S603 -- fixed local Docker and test-owned fixture args.
        [*base, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_ENV,
        timeout=12,
        check=False,
    )
    if run.returncode or len(run.stdout) > 256:
        raise RuntimeError(f"Fixture Docker {args[0]} failed")
    return run.stdout.strip()


def require_root(root: Path) -> None:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or not root.is_absolute()
        or root.resolve() != root
        or not root.is_relative_to("/var/lib/opsark-release-lab")
        or root == Path("/var/lib/opsark-release-lab")
    ):
        raise RuntimeError("An administrator-owned fixture laboratory is required")
    for path in (root, *root.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("The fixture laboratory path is not trusted")
    if root.stat().st_mode & 0o077:
        raise RuntimeError("The fixture laboratory must be private")


def write_runtime(workspace: Path, *, rich: bool, tls: bool = False, chain: bool = False):
    runtime = workspace / "runtime"
    runtime.mkdir(mode=0o755 if rich else 0o700)
    if rich:
        runtime.chmod(0o755)
    files = {"nginx.conf": fixture_runtime.WRAPPER}
    if chain:
        files = fixture_context.CHAIN_FIXTURE_FILES
    elif tls:
        files = fixture_context.TLS_FIXTURE_FILES
    elif rich:
        files = fixture_context.FIXTURE_FILES
    for relative, content in files.items():
        destination = runtime / relative
        destination.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        if rich:
            destination.parent.chmod(0o755)
        destination.write_bytes(content)
        destination.chmod(0o644)
    return len(files)


def generate_tls(directory: Path) -> None:
    """Generate a fresh disposable pair without reading the private key into the test process."""
    directory.mkdir(mode=0o700)
    certificate = directory / "cert.pem"
    private_key = directory / "key.pem"
    result = subprocess.run(  # noqa: S603 -- fixed openssl arguments and test-owned paths.
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=target.opsark.invalid",
            "-addext",
            "subjectAltName=DNS:target.opsark.invalid,DNS:control.opsark.invalid,DNS:unknown.opsark.invalid",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_ENV,
        timeout=12,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Could not generate a disposable TLS fixture")
    os.chown(directory, 0, 65534)
    directory.chmod(0o750)
    for path in (certificate, private_key):
        os.chown(path, 0, 65534)
        path.chmod(0o640)


def prepare_plan(
    root: Path,
    *,
    rich: bool,
    tls: bool = False,
    chain: bool = False,
    mismatched_pair: bool = False,
) -> tuple[Path, Path, Path, dict]:
    workspace = root / ("opsark-nginx-fixture-" + secrets.token_hex(8))
    workspace.mkdir(mode=0o700)
    marker = workspace / "opsark-isolated-fixture"
    marker.write_bytes(b"opsark-nginx-fixture-v1\n")
    marker.chmod(0o600)
    config = workspace / "etc/nginx/conf.d"
    config.mkdir(mode=0o755, parents=True)
    config.chmod(0o755)
    machine = workspace / "etc/machine-id"
    machine.write_text(secrets.token_hex(16) + "\n", encoding="ascii")
    machine.chmod(0o600)
    (workspace / "actions").mkdir(mode=0o700)
    dependencies = write_runtime(workspace, rich=rich, tls=tls, chain=chain)
    if chain:
        generate_chain_tls(workspace / "tls")
    elif tls:
        generate_tls(workspace / "tls")
        if mismatched_pair:
            other = workspace / "unmatched-tls"
            generate_tls(other)
            (other / "key.pem").replace(workspace / "tls/key.pem")
    target = config / fixture_runtime.TARGET
    target.write_bytes(ORIGINAL)
    target.chmod(0o644)
    candidate = workspace / "candidate.conf"
    candidate.write_bytes(CANDIDATE)
    candidate.chmod(0o600)
    backup, plan = [workspace / name for name in ("backup", "plan")]
    policy = fixture_action.fixture_policy(workspace)
    config_snapshot.capture(target, digest(ORIGINAL), backup, policy=policy)
    if rich:
        profile = ("--tls-chain",) if chain else ("--tls",) if tls else ()
        code, sealed = cli("seal-context", "--workspace", str(workspace), *profile)
        assert code == 0 and sealed["dependency_count"] == dependencies
        assert bool(sealed.get("tls")) == tls
        assert bool(sealed.get("tls_chain")) == chain
        if chain:
            assert len(set(sealed["leaf_sha256"].values())) == 3
        code, prepared = cli(
            "prepare-context",
            "--workspace",
            str(workspace),
            "--snapshot",
            str(backup),
            "--candidate",
            str(candidate),
            "--expected-sha256",
            digest(CANDIDATE),
            "--output",
            str(plan),
        )
        assert code == 0 and prepared["context_sha256"] == sealed["context_sha256"]
    else:
        prepared = config_snapshot.prepare(
            backup, candidate, digest(CANDIDATE), plan, policy=policy
        )
    return workspace, target, plan, prepared


def context_approval(workspace, image, plan, prepared, approval, *, refusal=False):
    return cli(
        "approve-context",
        "--workspace",
        str(workspace),
        "--plan",
        str(plan),
        "--image",
        image,
        "--expected-plan-id",
        prepared["plan_id"],
        "--expected-candidate-sha256",
        digest(CANDIDATE),
        "--output",
        str(approval),
        "--confirm",
        refusal=refusal,
    )


def prepare(
    root: Path, image: str, *, rich: bool, tls: bool = False, chain: bool = False
) -> tuple[Path, Path, Path, str]:
    workspace, target, plan, prepared = prepare_plan(root, rich=rich, tls=tls, chain=chain)
    approval = workspace / "approval"
    if rich:
        code, approved = context_approval(workspace, image, plan, prepared, approval)
        assert code == 0 and approved["context_sha256"] == prepared["context_sha256"]
    else:
        approved = config_snapshot.approve_plan(
            plan,
            image,
            str(prepared["plan_id"]),
            digest(CANDIDATE),
            approval,
            confirm=True,
            policy=fixture_action.fixture_policy(workspace),
        )
    return workspace, target, approval, str(approved["approval_id"])


@contextmanager
def run_fixture(workspace: Path, image: str, docker_config: str, *, check_baseline: bool = True):
    base = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", docker_config]
    image_state = (
        docker(
            base,
            "image",
            "inspect",
            "--format",
            '{{.Id}}\n{{json (index .Config "Volumes")}}',
            image,
        )
        .decode("ascii")
        .splitlines()
    )
    if image_state not in ([image, "null"], [image, "{}"]):
        raise RuntimeError("The isolated fixture image must not declare volumes")
    policy = fixture_action.fixture_policy(workspace)
    rich = fixture_context.has_context(policy)
    context = fixture_context.verify_context(policy) if rich else None
    tls = context is not None and (context.tls is not None or context.tls_chain is not None)
    wrapper = (
        f"type=bind,src={workspace}/runtime,dst=/fixture-runtime,readonly"
        if rich
        else f"type=bind,src={workspace}/runtime/nginx.conf,dst=/fixture-wrapper.conf,readonly"
    )
    command = fixture_runtime.CONTEXT_COMMAND if rich else fixture_runtime.NGINX_COMMAND
    tls_mount = (
        ("--mount", f"type=bind,src={workspace}/tls,dst=/fixture-tls,readonly") if tls else ()
    )
    container = docker(
        base,
        "run",
        "--detach",
        "--pull",
        "never",
        "--name",
        workspace.name,
        "--label",
        f"{fixture_runtime.LABEL}={workspace.name}",
        "--network",
        "none",
        "--ipc",
        "none",
        "--cgroupns",
        "private",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--pids-limit",
        "32",
        "--memory",
        "96m",
        "--memory-swap",
        "96m",
        "--cpus",
        "0.25",
        "--tmpfs",
        f"{fixture_runtime.STATE_DIR}:{fixture_runtime.TMPFS}",
        "--mount",
        f"type=bind,src={workspace}/etc/nginx/conf.d,dst=/fixture-sites,readonly",
        "--mount",
        wrapper,
        *tls_mount,
        "--entrypoint",
        command[0],
        image,
        *command[1:],
    ).decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise RuntimeError("The created fixture identity is not available")
    runtime = None
    try:
        runtime = fixture_runtime.FixtureRuntime(workspace, container, image, docker_config)
        if check_baseline:
            for _ in range(12):
                try:
                    if runtime.preflight():
                        break
                except fixture_runtime.RuntimeRefused:
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("The baseline fixture did not become ready")
        yield runtime
    finally:
        if runtime is not None:
            runtime.close()
        binding = (
            docker(
                base,
                "container",
                "inspect",
                "--format",
                '{{.Id}}\n{{index .Config.Labels "io.opsark.nginx.fixture"}}',
                container,
            )
            .decode("ascii")
            .splitlines()
        )
        if binding != [container, workspace.name]:
            raise RuntimeError("The fixture cleanup identity could not be established")
        docker(base, "rm", "--force", container)


def apply(workspace, approval, approval_id, runtime, callback=None):
    return fixture_action.apply_fixture(
        workspace,
        approval,
        approval_id,
        digest(CANDIDATE),
        confirm=True,
        preflight=lambda: runtime.approval_preflight(approval),
        runtime_fingerprint=runtime.fingerprint,
        context_reader=runtime.context_reader(),
        reload_and_verify=runtime.reload_and_verify if callback is None else callback,
    )


def cli(*args: str, refusal: bool = False) -> tuple[int, dict]:
    assert fixture_runtime.__file__
    result = subprocess.run(  # noqa: S603 -- exact tool path and disposable fixture arguments.
        [sys.executable, "-I", "-B", fixture_runtime.__file__, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=45,
        env=_ENV,
        check=False,
    )
    if refusal and result.returncode == 1 and not result.stdout:
        assert result.stderr == b"The isolated fixture action could not be confirmed.\n"
        return 1, {}
    if not result.stdout or len(result.stdout) > 2048 or result.stderr:
        raise RuntimeError("The isolated fixture CLI did not return a safe receipt")
    return result.returncode, json.loads(result.stdout)


def kill_before_receipt(workspace, approval, approval_id, runtime, target, *, after_reload):
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)

        def interrupt():
            if after_reload and runtime.reload_and_verify() is not True:
                os._exit(4)
            os.write(writer, b"1")
            signal.pause()
            return False

        try:
            apply(workspace, approval, approval_id, runtime, interrupt)
        except Exception:
            os._exit(2)
        os._exit(3)
    os.close(writer)
    try:
        ready, _, _ = select.select([reader], [], [], 25)
        if not ready or os.read(reader, 1) != b"1" or target.read_bytes() != CANDIDATE:
            raise RuntimeError("The durable action did not reach the interruption point")
    finally:
        os.close(reader)
        with suppress(ProcessLookupError):
            os.kill(child, signal.SIGKILL)
        _, status = os.waitpid(child, 0)
    if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
        raise RuntimeError("The interruption was not established")


def location(workspace, runtime):
    return (
        "--workspace",
        str(workspace),
        "--container",
        runtime.container,
        "--image",
        runtime.image,
    )


def worker(runtime):
    for _ in range(12):
        children = runtime._docker(
            "exec",
            runtime.container,
            "/usr/bin/python3",
            "-I",
            "-c",
            "from pathlib import Path;print(Path('/proc/1/task/1/children').read_text().strip())",
            limit=128,
        ).split()
        if len(children) == 1 and children[0].isdigit():
            return children[0]
        time.sleep(0.2)
    raise RuntimeError("The fixture worker identity could not be established")


def restore_args(workspace, runtime, original_approval, action_id, output):
    return (
        "approve-restore",
        *location(workspace, runtime),
        "--original-action-id",
        action_id,
        "--approval",
        str(original_approval),
        "--expected-original-sha256",
        digest(ORIGINAL),
        "--output",
        str(output),
        "--confirm",
    )


def original_records(workspace, action_id):
    directory = workspace / "actions"
    return {
        path.name: path.read_bytes()
        for role in ("intent", "result")
        if (path := directory / f"{action_id}.{role}.json").exists()
    }


def restore(workspace, runtime, target, original_approval, original, *, break_context=False):
    action_id = original["action_id"]
    immutable = original_records(workspace, action_id)
    previous_inode = target.stat().st_ino
    previous_worker = worker(runtime)
    output = workspace / "restore-approval"
    code, approval = cli(*restore_args(workspace, runtime, original_approval, action_id, output))
    assert code == 0 and approval["approval_status"] == "approved"
    assert approval["original_action_id"] == action_id
    assert approval["original_sha256"] == digest(ORIGINAL)
    assert worker(runtime) == previous_worker and target.stat().st_ino == previous_inode
    restore_id = approval["restore_action_id"]
    assert restore_id != action_id
    assert cli("restore-id", "--workspace", str(workspace), "--approval", str(output)) == (
        0,
        {"action_id": restore_id},
    )
    args = (
        "restore",
        *location(workspace, runtime),
        "--approval",
        str(output),
        "--expected-approval-id",
        approval["approval_id"],
        "--expected-original-sha256",
        digest(ORIGINAL),
        "--confirm",
    )
    if break_context:
        replace_dependency(workspace, "sites/control.conf")
        assert cli(*args, refusal=True)[0] == 1
        _, untouched = cli("status", "--workspace", str(workspace), "--action-id", restore_id)
        assert untouched["status"] == "missing"
        assert target.stat().st_ino == previous_inode and worker(runtime) == previous_worker
        assert original_records(workspace, action_id) == immutable
        return
    code, receipt = cli(*args)
    assert code == 0 and receipt["status"] == "verified" and receipt["action"] == "restore"
    assert receipt["action_id"] == restore_id and receipt["disk_status"] == "preimage"
    inode = target.stat().st_ino
    current_worker = worker(runtime)
    assert inode != previous_inode and current_worker != previous_worker
    assert cli(*args) == (0, receipt)
    assert target.stat().st_ino == inode and worker(runtime) == current_worker
    assert runtime._probe(b"original")
    assert original_records(workspace, action_id) == immutable
    _, historical = cli("status", "--workspace", str(workspace), "--action-id", action_id)
    assert historical == {**original, "disk_status": "preimage"}


def reject_new_disk_or_process(root, image, docker_config, *, rich, tls=False, chain=False):
    for replacement in ("inode", "process"):
        workspace, target, approval, approval_id = prepare(
            root, image, rich=rich, tls=tls, chain=chain
        )
        action_id = fixture_action.action_id_for_approval(workspace, approval)
        with run_fixture(workspace, image, docker_config) as runtime:
            kill_before_receipt(
                workspace, approval, approval_id, runtime, target, after_reload=True
            )
            if replacement == "inode":
                former = target.stat().st_ino
                staged = target.with_name(".same-bytes-fixture")
                staged.write_bytes(CANDIDATE)
                staged.chmod(0o644)
                staged.replace(target)
                assert target.stat().st_ino != former
            else:
                docker(runtime.base, "restart", "--timeout", "1", runtime.container)
                for _ in range(12):
                    with suppress(fixture_runtime.RuntimeRefused):
                        if runtime._probe(b"candidate"):
                            break
                    time.sleep(0.25)
                else:
                    raise RuntimeError("The restarted fixture did not become ready")
            assert runtime._probe(b"candidate")
            saved_worker = worker(runtime)
            original = original_records(workspace, action_id)
            code, record = cli("reconcile", *location(workspace, runtime), "--action-id", action_id)
            assert code == 1 and record["status"] == "unknown"
            assert record["disk_status"] == "candidate" and "reconciliation_status" not in record
            assert original_records(workspace, action_id) == original
            assert worker(runtime) == saved_worker


def apply_args(workspace, approval, approval_id, runtime):
    return (
        "apply",
        *location(workspace, runtime),
        "--approval",
        str(approval),
        "--expected-approval-id",
        approval_id,
        "--expected-candidate-sha256",
        digest(CANDIDATE),
        "--confirm",
    )


def replace_dependency(workspace, name, *, changed=False):
    path = workspace / "runtime" / name
    original_inode = path.stat().st_ino
    staged = path.with_name(".replaced-fixture")
    staged.write_bytes(path.read_bytes() + (b"\n# synthetic drift\n" if changed else b""))
    staged.chmod(0o644)
    staged.replace(path)
    assert path.stat().st_ino != original_inode


def reseal(workspace):
    seal = workspace / "runtime-context"
    (seal / "manifest.json").unlink()
    seal.rmdir()
    code, result = cli("seal-context", "--workspace", str(workspace))
    assert code == 0
    return result


def reject_stale_mounted_context(root, image, docker_config):
    workspace, target, _, initial = prepare_plan(root, rich=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        before = worker(runtime)
        # Docker still holds the original directory inode under the same source path.
        (workspace / "runtime").rename(workspace / "retired-runtime")
        write_runtime(workspace, rich=True)
        replacement = reseal(workspace)
        assert replacement["context_sha256"] != initial["context_sha256"]
        plan = workspace / "new-plan"
        code, prepared = cli(
            "prepare-context",
            "--workspace",
            str(workspace),
            "--snapshot",
            str(workspace / "backup"),
            "--candidate",
            str(workspace / "candidate.conf"),
            "--expected-sha256",
            digest(CANDIDATE),
            "--output",
            str(plan),
        )
        assert code == 0 and prepared["context_sha256"] == replacement["context_sha256"]
        approval = workspace / "new-approval"
        code, approved = context_approval(workspace, image, plan, prepared, approval)
        assert code == 0
        assert (
            cli(*apply_args(workspace, approval, approved["approval_id"], runtime), refusal=True)[0]
            == 1
        )
        action_id = fixture_action.action_id_for_approval(workspace, approval)
        _, status = cli("status", "--workspace", str(workspace), "--action-id", action_id)
        assert status["status"] == "missing"
        assert target.read_bytes() == ORIGINAL and worker(runtime) == before


def reject_context_drift(root, image, docker_config):
    workspace, target, plan, prepared = prepare_plan(root, rich=True)
    approval = workspace / "approval"
    replace_dependency(workspace, "includes/sites.conf")
    assert context_approval(workspace, image, plan, prepared, approval, refusal=True)[0] == 1
    replacement = reseal(workspace)
    assert replacement["context_sha256"] != prepared["context_sha256"]
    assert context_approval(workspace, image, plan, prepared, approval, refusal=True)[0] == 1
    assert not approval.exists() and target.read_bytes() == ORIGINAL

    workspace, target, approval, approval_id = prepare(root, image, rich=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        before = worker(runtime)
        action_id = fixture_action.action_id_for_approval(workspace, approval)
        replace_dependency(workspace, "sites/control.conf")
        assert cli(*apply_args(workspace, approval, approval_id, runtime), refusal=True)[0] == 1
        _, status = cli("status", "--workspace", str(workspace), "--action-id", action_id)
        assert status["status"] == "missing"
        assert target.read_bytes() == ORIGINAL and worker(runtime) == before

    workspace, target, approval, approval_id = prepare(root, image, rich=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        before = worker(runtime)

        def drift_at_signal():
            replace_dependency(workspace, "sites/control.conf")
            return runtime.reload_and_verify()

        action = apply(workspace, approval, approval_id, runtime, drift_at_signal)
        assert action["status"] == "unknown" and action["disk_status"] == "candidate"
        assert worker(runtime) == before

    for interrupted in (True, False):
        workspace, target, approval, approval_id = prepare(root, image, rich=True)
        action_id = fixture_action.action_id_for_approval(workspace, approval)
        with run_fixture(workspace, image, docker_config) as runtime:
            if interrupted:
                kill_before_receipt(
                    workspace, approval, approval_id, runtime, target, after_reload=True
                )
            else:
                assert cli(*apply_args(workspace, approval, approval_id, runtime))[0] == 0
            before = worker(runtime)
            records = original_records(workspace, action_id)
            replace_dependency(workspace, "sites/default.conf", changed=True)
            if interrupted:
                code, status = cli(
                    "reconcile", *location(workspace, runtime), "--action-id", action_id
                )
                assert code == 1 and status["status"] == "unknown"
                assert "reconciliation_status" not in status
            else:
                output = workspace / "restore-refused"
                assert (
                    cli(
                        *restore_args(workspace, runtime, approval, action_id, output), refusal=True
                    )[0]
                    == 1
                )
                assert not output.exists()
            assert original_records(workspace, action_id) == records
            assert target.read_bytes() == CANDIDATE and worker(runtime) == before

    workspace, target, approval, approval_id = prepare(root, image, rich=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        code, original = cli(*apply_args(workspace, approval, approval_id, runtime))
        assert code == 0
        restore(workspace, runtime, target, approval, original, break_context=True)


def reject_bad_tls(root, image, docker_config):
    workspace, target, plan, prepared = prepare_plan(
        root, rich=True, tls=True, mismatched_pair=True
    )
    code, result = cli(
        "validate-context", "--workspace", str(workspace), "--plan", str(plan), "--image", image
    )
    assert code == 1 and result["syntax_status"] == "failed"
    approval = workspace / "refused-approval"
    assert context_approval(workspace, image, plan, prepared, approval, refusal=True)[0] == 1
    assert not approval.exists() and target.read_bytes() == ORIGINAL

    workspace, target, approval, approval_id = prepare(root, image, rich=True, tls=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        before = worker(runtime)
        action_id = fixture_action.action_id_for_approval(workspace, approval)
        (workspace / "tls/key.pem").chmod(0o644)
        assert cli(*apply_args(workspace, approval, approval_id, runtime), refusal=True)[0] == 1
        _, status = cli("status", "--workspace", str(workspace), "--action-id", action_id)
        assert status["status"] == "missing"
        assert target.read_bytes() == ORIGINAL and worker(runtime) == before


def native_tls(runtime, host):
    assert host in fixture_context.CHAIN_HOSTS.values()
    result = subprocess.run(  # noqa: S603 -- fixed Docker, pinned fixture, fixed loopback/SNI.
        [
            *runtime.base,
            "exec",
            runtime.container,
            "/usr/bin/openssl",
            "s_client",
            "-connect",
            "127.0.0.1:18087",
            "-servername",
            host,
            "-verify_hostname",
            host,
            "-verify_return_error",
            "-verifyCAfile",
            "/fixture-tls/root.pem",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-no_ticket",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        env=_ENV,
        check=False,
    )
    return result.returncode == 0


def wait_default_tls(runtime):
    for _ in range(12):
        if native_tls(runtime, fixture_context.CHAIN_HOSTS["default"]):
            return
        time.sleep(0.25)
    raise RuntimeError("The unaffected default TLS fixture did not become ready")


def replace_chain_material(workspace):
    # Only the disposable fixture directory is moved. No private key bytes are read.
    (workspace / "tls").rename(workspace / ("retired-tls-" + secrets.token_hex(6)))
    generate_chain_tls(workspace / "tls")


def seal_chain(workspace):
    seal = workspace / "runtime-context"
    (seal / "manifest.json").unlink()
    seal.rmdir()
    code, result = cli("seal-context", "--workspace", str(workspace), "--tls-chain")
    assert code == 0 and len(set(result["leaf_sha256"].values())) == 3
    return result


def prepare_rotated(workspace, image, sealed):
    plan, approval = workspace / "rotated-plan", workspace / "rotated-approval"
    code, prepared = cli(
        "prepare-context",
        "--workspace",
        str(workspace),
        "--snapshot",
        str(workspace / "backup"),
        "--candidate",
        str(workspace / "candidate.conf"),
        "--expected-sha256",
        digest(CANDIDATE),
        "--output",
        str(plan),
    )
    assert code == 0 and prepared["context_sha256"] == sealed["context_sha256"]
    code, approved = context_approval(workspace, image, plan, prepared, approval)
    assert code == 0
    return approval, approved["approval_id"]


def assert_missing(workspace, action_id):
    code, status = cli("status", "--workspace", str(workspace), "--action-id", action_id)
    assert code == 1 and status["status"] == "missing"


def reject_missing_intermediate(root, image, docker_config):
    workspace, target, _, _ = prepare_plan(root, rich=True, chain=True)
    with run_fixture(workspace, image, docker_config) as runtime:
        chain_file = workspace / "tls/target-chain.pem"
        leaf, rest = chain_file.read_bytes().split(b"-----END CERTIFICATE-----\n", 1)
        assert rest.startswith(b"-----BEGIN CERTIFICATE-----\n")
        chain_file.write_bytes(leaf + b"-----END CERTIFICATE-----\n")
        docker(runtime.base, "restart", "--timeout", "1", runtime.container)
        wait_default_tls(runtime)
        assert not native_tls(runtime, fixture_context.CHAIN_HOSTS["target"])
        assert native_tls(runtime, fixture_context.CHAIN_HOSTS["control"])
        assert target.read_bytes() == ORIGINAL
        seal = workspace / "runtime-context"
        (seal / "manifest.json").unlink()
        seal.rmdir()
        assert (
            cli("seal-context", "--workspace", str(workspace), "--tls-chain", refusal=True)[0] == 1
        )
        assert not seal.exists()


def reject_swapped_names(root, image, docker_config):
    workspace, target, _, _ = prepare_plan(root, rich=True, chain=True)
    for ending in ("-chain.pem", "-key.pem"):
        first, second = [workspace / "tls" / (role + ending) for role in ("target", "control")]
        parked = workspace / ("parked" + ending)
        first.rename(parked)
        second.rename(first)
        parked.rename(second)
    approval, approval_id = prepare_rotated(workspace, image, seal_chain(workspace))
    action_id = fixture_action.action_id_for_approval(workspace, approval)
    with run_fixture(workspace, image, docker_config, check_baseline=False) as runtime:
        wait_default_tls(runtime)
        assert not native_tls(runtime, fixture_context.CHAIN_HOSTS["target"])
        assert not native_tls(runtime, fixture_context.CHAIN_HOSTS["control"])
        saved_worker = worker(runtime)
        assert cli(*apply_args(workspace, approval, approval_id, runtime), refusal=True)[0] == 1
        assert_missing(workspace, action_id)
        assert target.read_bytes() == ORIGINAL and worker(runtime) == saved_worker


def reject_stale_rotation(root, image, docker_config):
    workspace, target, approval, approval_id = prepare(root, image, rich=True, chain=True)
    old_id = fixture_action.action_id_for_approval(workspace, approval)
    with run_fixture(workspace, image, docker_config) as runtime:
        old_args = apply_args(workspace, approval, approval_id, runtime)
        saved_worker = worker(runtime)
        replace_chain_material(workspace)
        assert native_tls(runtime, fixture_context.CHAIN_HOSTS["target"])
        assert cli(*old_args, refusal=True)[0] == 1
        rotated, rotated_id = prepare_rotated(workspace, image, seal_chain(workspace))
        assert cli(*old_args, refusal=True)[0] == 1
        assert cli(*apply_args(workspace, rotated, rotated_id, runtime), refusal=True)[0] == 1
        assert_missing(workspace, old_id)
        new_id = fixture_action.action_id_for_approval(workspace, rotated)
        assert_missing(workspace, new_id)
        assert worker(runtime) == saved_worker and target.read_bytes() == ORIGINAL

    with run_fixture(workspace, image, docker_config) as runtime:
        code, original = cli(*apply_args(workspace, rotated, rotated_id, runtime))
        assert code == 0 and original["action_id"] == new_id and runtime._probe(b"candidate")
        original_state = original_records(workspace, new_id)
        output = workspace / "pre-rotation-restore"
        code, receipt = cli(*restore_args(workspace, runtime, rotated, new_id, output))
        assert code == 0 and receipt["approval_status"] == "approved"
        saved_worker = worker(runtime)
        replace_chain_material(workspace)
        seal_chain(workspace)
        assert (
            cli(
                "restore",
                *location(workspace, runtime),
                "--approval",
                str(output),
                "--expected-approval-id",
                receipt["approval_id"],
                "--expected-original-sha256",
                digest(ORIGINAL),
                "--confirm",
                refusal=True,
            )[0]
            == 1
        )
        assert_missing(workspace, receipt["restore_action_id"])
        assert original_records(workspace, new_id) == original_state
        assert worker(runtime) == saved_worker and target.read_bytes() == CANDIDATE


def reject_bad_chain(root, image, docker_config):
    reject_missing_intermediate(root, image, docker_config)
    reject_swapped_names(root, image, docker_config)
    reject_stale_rotation(root, image, docker_config)


def exercise(
    root: Path, image: str, docker_config: str, *, rich: bool, tls: bool, chain: bool
) -> dict:
    repeated_callbacks = []

    def unexpected_callback():
        repeated_callbacks.append(True)
        return False

    workspace, target, approval, approval_id = prepare(root, image, rich=rich, tls=tls, chain=chain)
    with run_fixture(workspace, image, docker_config) as runtime:
        original_inode = target.stat().st_ino
        args = apply_args(workspace, approval, approval_id, runtime)
        exit_code, success = cli(*args)
        assert exit_code == 0
        assert success["status"] == "verified" and success["disk_status"] == "candidate"
        assert cli(
            "status", "--workspace", str(workspace), "--action-id", success["action_id"]
        ) == (0, success)
        inode = target.stat().st_ino
        assert inode != original_inode
        assert cli(*args) == (0, success)
        assert apply(workspace, approval, approval_id, runtime, unexpected_callback) == success
        assert target.stat().st_ino == inode and runtime._probe(b"candidate")
        restore(workspace, runtime, target, approval, success)

    for after_reload in (False, True):
        workspace, target, approval, approval_id = prepare(
            root, image, rich=rich, tls=tls, chain=chain
        )
        code, lookup = cli("action-id", "--workspace", str(workspace), "--approval", str(approval))
        assert code == 0 and set(lookup) == {"action_id"}
        action_id = lookup["action_id"]
        with run_fixture(workspace, image, docker_config) as runtime:
            original_inode = target.stat().st_ino
            kill_before_receipt(
                workspace, approval, approval_id, runtime, target, after_reload=after_reload
            )
            code, unknown = cli("status", "--workspace", str(workspace), "--action-id", action_id)
            assert code == 1
            assert unknown["status"] == "unknown" and unknown["disk_status"] == "candidate"
            expected = b"candidate" if after_reload else b"original"
            assert unknown["action_id"] == action_id and runtime._probe(expected)
            inode = target.stat().st_ino
            assert inode != original_inode
            assert apply(workspace, approval, approval_id, runtime, unexpected_callback) == unknown
            assert target.stat().st_ino == inode and runtime._probe(expected)
            original = original_records(workspace, action_id)
            saved_worker = worker(runtime)
            no_approval = workspace / "unresolved-restore"
            assert (
                cli(
                    *restore_args(workspace, runtime, approval, action_id, no_approval),
                    refusal=True,
                )[0]
                == 1
            )
            assert not no_approval.exists()
            reconciliation = ("reconcile", *location(workspace, runtime), "--action-id", action_id)
            observed = {**unknown, "reconciliation_status": "verified"} if after_reload else unknown
            exit_code = 0 if after_reload else 1
            assert cli(*reconciliation) == (exit_code, observed)
            assert cli(*reconciliation) == (exit_code, observed)
            assert target.stat().st_ino == inode and worker(runtime) == saved_worker
            assert original_records(workspace, action_id) == original
            if after_reload:
                restore(workspace, runtime, target, approval, observed)
    assert not repeated_callbacks
    reject_new_disk_or_process(root, image, docker_config, rich=rich, tls=tls, chain=chain)
    if chain:
        reject_bad_chain(root, image, docker_config)
    elif tls:
        reject_bad_tls(root, image, docker_config)
    elif rich:
        reject_context_drift(root, image, docker_config)
        reject_stale_mounted_context(root, image, docker_config)
    return {
        "verified_real_nginx_reload": True,
        "target_control_and_unknown_host_verified": True,
        "verified_retry_preserved_original_receipt": True,
        "interrupted_after_write_before_reload": True,
        "interrupted_after_runtime_verified_before_receipt": True,
        "interrupted_retry_did_not_write_or_reload": True,
        "status_discloses_disk_and_unknown_separately": True,
        "reconciled_only_when_same_runtime_actually_applied_change": True,
        "reconciliation_did_not_write_or_reload": True,
        "same_bytes_replaced_inode_and_restarted_process_rejected": True,
        "restore_required_independent_approval": True,
        "restore_kept_original_receipt_and_had_one_reload": True,
        "sealed_includes_context_verified": rich,
        "dependency_drift_refused_at_approval_apply_reload_reconcile_and_restore": rich
        and not tls
        and not chain,
        "same_path_resealed_context_with_stale_mount_refused": rich and not tls and not chain,
        "tls_handshakes_sni_and_leaf_pin_verified": tls or chain,
        "tls_mismatched_private_key_and_permissions_rejected": tls,
        "distinct_sni_leaf_pins_and_exact_served_chains_verified": chain,
        "tls_chain_faults_and_stale_rotation_approvals_rejected": chain,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    parser.add_argument("--rich-context", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--tls-context", action="store_true")
    modes.add_argument("--chain-context", action="store_true")
    args = parser.parse_args()
    require_root(args.root)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise RuntimeError("A pinned fixture image is required")
    with TemporaryDirectory(prefix="opsark-action-docker-", dir="/tmp") as config:
        print(
            json.dumps(
                exercise(
                    args.root,
                    args.image,
                    config,
                    rich=args.rich_context or args.tls_context or args.chain_context,
                    tls=args.tls_context,
                    chain=args.chain_context,
                ),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
