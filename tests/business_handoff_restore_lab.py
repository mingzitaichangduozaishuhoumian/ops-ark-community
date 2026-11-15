"""Rehearse cold business handoff history in a fresh offline OpsArk container."""

import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
TRANSFER = ROOT / "deploy" / "observer" / "store_transfer.py"
LAB = Path("/var/lib/opsark-release-lab")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
UID = 10001
PYTHON = "/app/.venv/bin/python"
SHA256 = re.compile(r"[0-9a-f]{64}")
KEY = re.compile(r"[0-9a-f]{32}")
RECEIPT = re.compile(r"br-[0-9a-f]{32}")
STAGES = {"startup", "token", "auth", "inventory", "history", "report", "recheck", "export", "ai"}
PROBE = """import hashlib
import http.client
import json
import os
import stat
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlencode


def need(condition, stage):
    if not condition:
        print(json.dumps({'error': stage}))
        raise SystemExit


def call(method, url, *, authorized=True, payload=None, timeout=3):
    headers = {'Authorization': 'Bearer ' + token} if authorized else {}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    with closing(http.client.HTTPConnection('127.0.0.1', 8010, timeout=timeout)) as conn:
        conn.request(method, url, None if payload is None else json.dumps(payload), headers)
        reply = conn.getresponse()
        body = reply.read(2_097_153)
        need(len(body) <= 2_097_152, 'report')
        return reply.status, reply.getheader('Cache-Control'), body


def digest(body):
    return hashlib.sha256(body).hexdigest()


expected = json.load(sys.stdin)
token_path = Path('/app/data/access-token')
deadline = time.monotonic() + 16
while time.monotonic() < deadline:
    try:
        if call('GET', '/api/status', authorized=False, timeout=0.5)[0] == 200:
            break
    except (OSError, http.client.HTTPException):
        pass
    time.sleep(0.2)
else:
    need(False, 'startup')
metadata = token_path.lstat()
need(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
     and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
     and 32 <= metadata.st_size <= 256, 'token')
token = token_path.read_text(encoding='ascii').strip()
need(len(token) >= 32, 'token')
fingerprint = digest(token.encode('ascii'))
need(fingerprint != expected.get('source_token_sha256'), 'token')
report = '/api/reports/' + expected['report_id']
params = {'job_id': expected['job_id']}
history = report + '/handoff-rechecks?' + urlencode(params)
need(call('GET', history, authorized=False)[0] == 401, 'auth')
code, _, body = call('GET', '/api/hosts')
need(code == 200 and all(row['source'] == 'replay' for row in json.loads(body)), 'inventory')
code, _, body = call('GET', '/api/ai/status')
need(code == 200 and json.loads(body)['configured'] is False, 'ai')
code, cache, body = call('GET', history)
need(code == 200 and cache == 'no-store' and json.loads(body) == {
    'can_run': False, 'rechecks': expected['history'],
}, 'history')
need(call('POST', report + '/handoff-rechecks', payload=params)[0] == 409, 'recheck')
code, cache, body = call('GET', report)
need(code == 200 and cache == 'no-store' and digest(body) == expected['report_sha256'], 'report')
code, _, body = call('GET', '/api/reports')
need(code == 200 and [row['id'] for row in json.loads(body)] == [expected['report_id']], 'report')
for receipt, expected_sha in expected['export_sha256'].items():
    receipt_path = '/api/reports/' + receipt
    need(call('GET', receipt_path)[0] == 404, 'report')
    need(call('POST', receipt_path + '/explain', payload={'confirm_send': True})[0] == 404, 'ai')
    export = report + '/handoff?' + urlencode({**params, 'recheck_report_id': receipt})
    code, cache, body = call('GET', export)
    need(code == 200 and cache == 'no-store' and digest(body) == expected_sha, 'export')
print(json.dumps({'count': len(expected['history']), 'token_sha256': fingerprint}))
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_paths(root, snapshot, expected):
    require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and root.is_absolute()
        and root.resolve() == root
        and root.is_relative_to(LAB)
        and root != LAB,
        "An administrator-owned fixture laboratory is required",
    )
    require(
        snapshot.parent == root
        and snapshot.resolve() == snapshot
        and expected == snapshot.with_name(snapshot.name + ".expected.json"),
        "Snapshot and expectation must be direct children of the private fixture stage",
    )
    for path in (snapshot, root, *root.parents):
        info = path.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "The fixture path is not trusted",
        )
    require(
        not (snapshot.stat().st_mode | root.stat().st_mode) & 0o077,
        "The fixture paths must be private",
    )


def read_expected(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o077
            and info.st_nlink == 1
            and 0 < info.st_size <= 16_384,
            "The fixture expectation is not a private ordinary file",
        )
        raw = handle.read(16_385)
    require(len(raw) == info.st_size, "The fixture expectation changed while reading")
    data = json.loads(raw)
    required = {"report_id", "job_id", "history", "export_sha256", "report_sha256"}
    require(
        isinstance(data, dict) and required <= data.keys() <= required | {"source_token_sha256"},
        "The fixture expectation has unexpected fields",
    )
    require(
        all(
            isinstance(data[field], str) and KEY.fullmatch(data[field])
            for field in ("report_id", "job_id")
        )
        and all(
            isinstance(data[field], str) and SHA256.fullmatch(data[field])
            for field in ("report_sha256", "source_token_sha256")
            if field in data
        ),
        "The fixture report, job or digest format is invalid",
    )
    history = data["history"]
    require(
        isinstance(history, list) and len(history) == 4, "Exactly four fixture receipts required"
    )
    for row, state, count in zip(
        history, ("passed", "pending", "failed", "failed"), (2, 1, 1, 1), strict=True
    ):
        require(
            isinstance(row, dict)
            and set(row) == {"id", "at", "status", "configured_checks", "matched_checks"}
            and isinstance(row["id"], str)
            and RECEIPT.fullmatch(row["id"])
            and isinstance(row["at"], str)
            and len(row["at"]) <= 64
            and (row["status"], row["configured_checks"], row["matched_checks"])
            == (state, 2, count),
            "The fixture receipt metadata is invalid",
        )
    exports = data["export_sha256"]
    require(
        isinstance(exports, dict)
        and len(exports) == 4
        and set(exports) == {row["id"] for row in history}
        and all(isinstance(value, str) and SHA256.fullmatch(value) for value in exports.values()),
        "The fixture export digests are invalid",
    )
    return data, hashlib.sha256(raw).hexdigest()


def run(argv, operation, *, payload=None, timeout=30):
    result = subprocess.run(  # noqa: S603 -- exact archived tool or private fixture Docker command.
        argv,
        input=payload,
        capture_output=True,
        env=ENV,
        timeout=timeout,
        check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= 65_536, operation + " failed")
    return result.stdout


def transfer(operation, *paths):
    command = [sys.executable, "-I", "-B", str(TRANSFER), operation, *map(str, paths)]
    result = json.loads(run(command, "Offline " + operation, timeout=90))
    require(
        result.get("operation") == operation
        and result.get("status") == "complete"
        and result.get("database_count") == 10,
        "The offline tool did not verify ten stores",
    )
    return result["databases"]


def file_hash(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and not info.st_mode & 0o077,
            "The cold source file is not private",
        )
        return hashlib.file_digest(handle, "sha256").hexdigest()


def snapshot_hashes(path, names):
    return {name: file_hash(path / name) for name in (*names, "manifest.json")}


def offline_records(directory, expected):
    report_id, job_id = expected["report_id"], expected["job_id"]
    reports = (directory / "reports.sqlite3").as_uri() + "?mode=ro&immutable=1"
    patches = (directory / "patches.sqlite3").as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(reports, uri=True)) as db:
        require(
            db.execute("SELECT id FROM reports").fetchall() == [(report_id,)],
            "The original investigation was not retained",
        )
        receipts = db.execute("SELECT id, report_id, job_id FROM handoff_receipts").fetchall()
        require(
            len(receipts) == 4
            and set(receipts) == {(row["id"], report_id, job_id) for row in expected["history"]},
            "The receipt records lost their original report or task binding",
        )
    with closing(sqlite3.connect(patches, uri=True)) as db:
        retained = db.execute(
            "SELECT 1 FROM patch_jobs j JOIN patch_handoff_audit a "
            "ON a.host_id=j.host_id AND a.job_id=j.job_id "
            "WHERE j.job_id=? AND j.status='verified' "
            "AND a.unknown_at IS NOT NULL AND a.reconciled_at IS NOT NULL",
            (job_id,),
        ).fetchall()
        require(retained == [(1,)], "The original reconciled task and approval were not retained")


def isolated_api(docker, recovered, image, expected):
    name = "opsark-handoff-restore-" + secrets.token_hex(10)
    image_info = docker(
        "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
    )
    require(
        image_info.decode("ascii").split() in ([image, "null"], [image, "{}"]),
        "The recovery image must be pinned and declare no volumes",
    )
    empty_environment = (
        "OPSARK_TOKEN",
        "OPSARK_INVENTORY",
        "OPSARK_PATCH_INVENTORY",
        "OPSARK_AUTOMATION_POLICY",
        "OPSARK_AI_BASE_URL",
        "OPSARK_AI_KEY",
        "OPSARK_AI_KEY_FILE",
        "OPSARK_AI_MODEL",
        "OPSARK_VULNERABILITY_WEBHOOK_URL",
        "OPSARK_VULNERABILITY_WEBHOOK_KEY_FILE",
    )
    container = (
        docker(
            "create",
            "--name",
            name,
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--user",
            f"{UID}:{UID}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--ipc",
            "none",
            "--pids-limit",
            "64",
            "--memory",
            "192m",
            "--cpus",
            "0.5",
            "--no-healthcheck",
            "--log-driver",
            "none",
            "--mount",
            f"type=bind,src={recovered},dst=/app/data",
            "--env",
            "OPSARK_DATA_DIR=/app/data",
            "--env",
            "OPSARK_AI_PROVIDER=openai",
            "--env",
            "OPSARK_OBSERVE_ENABLED=0",
            "--env",
            "OPSARK_WEB_OBSERVE_ENABLED=0",
            "--env",
            "OPSARK_VULNERABILITY_SCAN_ENABLED=0",
            *(item for key in empty_environment for item in ("--env", key + "=")),
            "--entrypoint",
            PYTHON,
            image,
            "-I",
            "-B",
            "-m",
            "uvicorn",
            "opsark.main:app",
            "--app-dir",
            "/app/src",
            "--host",
            "127.0.0.1",
            "--port",
            "8010",
            "--no-access-log",
        )
        .decode("ascii")
        .strip()
    )
    require(SHA256.fullmatch(container), "The owned recovery container identity was not returned")
    try:
        bindings = (
            docker(
                "inspect",
                "--format",
                "{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} "
                "{{.Config.User}} {{json .HostConfig.PortBindings}} {{json .Mounts}}",
                container,
            )
            .decode("ascii")
            .split(maxsplit=4)
        )
        require(
            bindings[:3] == ["none", "true", f"{UID}:{UID}"]
            and json.loads(bindings[3]) in (None, {}),
            "The recovery controller is not isolated",
        )
        mounts = json.loads(bindings[4])
        require(
            len(mounts) == 1
            and mounts[0]["Type"] == "bind"
            and mounts[0]["Source"] == str(recovered)
            and mounts[0]["Destination"] == "/app/data",
            "The recovery controller has an unexpected mount",
        )

        def probe():
            result = json.loads(
                docker(
                    "exec",
                    "-i",
                    container,
                    PYTHON,
                    "-I",
                    "-B",
                    "-c",
                    PROBE,
                    payload=json.dumps(expected).encode("ascii"),
                )
            )
            stage = result.get("error")
            if isinstance(stage, str) and stage in STAGES:
                raise RuntimeError(f"Loopback recovery proof failed ({stage})")
            require(
                set(result) == {"count", "token_sha256"}
                and result["count"] == 4
                and SHA256.fullmatch(result["token_sha256"]),
                "Invalid loopback proof result",
            )
            return result

        docker("start", container)
        before = probe()
        docker("restart", "-t", "5", container)
        require(probe() == before, "The restored controller identity changed across restart")
    finally:
        docker("rm", "-f", container)


def exercise(root, snapshot, expected_path, image):
    validate_paths(root, snapshot, expected_path)
    expected, expectation_hash = read_expected(expected_path)
    source = transfer("verify", snapshot)
    hashes = snapshot_hashes(snapshot, source)
    offline_records(snapshot, expected)
    with TemporaryDirectory(prefix="handoff-restore-", dir=root) as temporary:
        workspace = Path(temporary)
        recovered = workspace / "recovered"
        staged = transfer("rehearse", snapshot, recovered)
        require(
            transfer("verify", recovered) == staged and set(source) == set(staged),
            "The independent restored copy did not verify",
        )
        require(
            all(
                source[name][field] == staged[name][field]
                for name in source
                for field in ("table_count", "row_count")
            ),
            "Store shape changed during restore",
        )
        offline_records(recovered, expected)
        require(
            {path.name for path in recovered.iterdir()} == {*staged, "manifest.json"},
            "The rehearsal contains files outside the approved store scope",
        )
        (recovered / "manifest.json").unlink()
        for name in staged:
            path = recovered / name
            path.chmod(0o600)
            os.chown(path, UID, UID)
        os.chown(recovered, UID, UID)

        def docker(*args, payload=None):
            return run(
                [
                    "/usr/bin/docker",
                    "--host",
                    "unix:///var/run/docker.sock",
                    "--config",
                    str(workspace),
                    *args,
                ],
                "Fixture Docker " + args[0],
                payload=payload,
                timeout=35,
            )

        isolated_api(docker, recovered, image, expected)
    require(
        transfer("verify", snapshot) == source
        and snapshot_hashes(snapshot, source) == hashes
        and file_hash(expected_path) == expectation_hash,
        "The cold source was changed",
    )
    return {
        "databases_verified": len(source),
        "receipts_verified": len(expected["history"]),
        "original_report_and_reconciliation_retained": True,
        "historical_exports_matched_before_and_after_restart": True,
        "read_only_history_without_live_targets": True,
        "no_receipt_in_reports_or_ai": True,
        "first_run_token_created": True,
        "source_snapshot_unchanged": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "Use a locally pinned image ID")
        proof = exercise(args.root, args.snapshot, args.expected, args.image)
        print(json.dumps(proof, sort_keys=True))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ):
        print("The isolated handoff recovery fixture could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
