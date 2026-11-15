"""Restore historical SSH defense metadata with fresh synthetic local credentials."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opsark_restore_lab", ROOT / "tests" / "business_handoff_restore_lab.py"
)
assert SPEC is not None and SPEC.loader is not None
restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore)
require = restore.require
ID = re.compile(r"[0-9a-f]{32}")
SHA256 = re.compile(r"[0-9a-f]{64}")
HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
UID = 10001
PYTHON = "/app/.venv/bin/python"
QUERY = (
    "SELECT host_id,host_scope,action_id,status,remaining_ms,observed_at "
    "FROM ssh_defense_observations ORDER BY host_id,host_scope,action_id"
)
EMPTY_ENV = (
    "OPSARK_TOKEN",
    "OPSARK_PATCH_INVENTORY",
    "OPSARK_AUTOMATION_POLICY",
    "OPSARK_AI_BASE_URL",
    "OPSARK_AI_KEY",
    "OPSARK_AI_KEY_FILE",
    "OPSARK_AI_MODEL",
    "OPSARK_VULNERABILITY_WEBHOOK_URL",
    "OPSARK_VULNERABILITY_WEBHOOK_KEY_FILE",
)
PROBE = """import hashlib
import http.client
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path


def need(condition, stage):
    if not condition:
        print(json.dumps({'error': stage}))
        raise SystemExit


def call(method, path, *, authorized=True, payload=None, timeout=8):
    headers = {'Authorization': 'Bearer ' + token} if authorized else {}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    with closing(http.client.HTTPConnection('127.0.0.1', 8010, timeout=timeout)) as conn:
        conn.request(method, path, None if payload is None else json.dumps(payload), headers)
        reply = conn.getresponse()
        raw = reply.read(65537)
        need(len(raw) <= 65536, 'api_size')
        return reply.status, reply.getheader('Cache-Control'), json.loads(raw)


def cached():
    uri = Path('/app/data/security.sqlite3').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        rows = db.execute(QUERY).fetchall()
    need([list(row) for row in rows] == [expected['cache_row']], 'cache')


expected = json.load(sys.stdin)
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
path = Path('/app/data/access-token')
info = path.lstat()
need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
     and stat.S_IMODE(info.st_mode) == 0o600 and 32 <= info.st_size <= 256, 'token')
token = path.read_text(encoding='ascii').strip()
fingerprint = hashlib.sha256(token.encode('ascii')).hexdigest()
need(len(token) >= 32 and fingerprint != expected['source_token_sha256'], 'token')
endpoint = '/api/hosts/' + expected['host_id'] + '/ssh-defense/actions'
need(call('GET', endpoint, authorized=False)[0] == 401, 'auth')
code, _, configured = call('GET', '/api/hosts')
enrolled = [row for row in configured if row['source'] == 'ssh']
need(code == 200 and enrolled == [expected['host_public']], 'registration')
code, _, ai = call('GET', '/api/ai/status')
need(code == 200 and ai['configured'] is False, 'ai')
history = {'host_id': expected['host_id'], 'actions': [
    {'action_id': expected['action_id'], 'last_observed': expected['last_observed']},
]}
cached()
code, cache, body = call('GET', endpoint)
need(code == 200 and cache == 'no-store' and body == history, 'history')
code, cache, body = call('POST', endpoint + '/' + expected['action_id'] + '/status', payload={})
need(code == 200 and cache == 'no-store' and set(body) == {
    'host_id','action_id','status','remaining_ms','checked_at','last_observed',
} and body['host_id'] == expected['host_id'] and body['action_id'] == expected['action_id']
    and body['status'] == 'unavailable' and body['remaining_ms'] is None
    and body['last_observed'] == expected['last_observed'], 'unavailable')
need(datetime.fromisoformat(body['checked_at']) > datetime.fromisoformat(
    expected['last_observed']['observed_at']), 'timestamp')
cached()
code, _, body = call('GET', endpoint)
need(code == 200 and body == history, 'history')
print(json.dumps({'token_sha256': fingerprint, 'cache_rows': 1}))
""".replace("db.execute(QUERY)", "db.execute(" + repr(QUERY) + ")")


def compact_digest(value):
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def read_expected(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and not info.st_mode & 0o077
            and 0 < info.st_size <= 16_384,
            "The recovery expectation must be a private ordinary file",
        )
        raw = handle.read(16_385)
    require(len(raw) == info.st_size, "Recovery expectation changed while reading")
    value = json.loads(raw)
    required = {
        "host_id",
        "action_id",
        "host_public",
        "known_hosts",
        "last_observed",
        "cache_row",
        "source_token_sha256",
    }
    optional = {"known_hosts_sha256", "cache_row_sha256"}
    require(
        isinstance(value, dict) and required <= value.keys() <= required | optional,
        "Unexpected recovery expectation fields",
    )
    require(
        isinstance(value["host_id"], str)
        and HOST_ID.fullmatch(value["host_id"])
        and isinstance(value["action_id"], str)
        and ID.fullmatch(value["action_id"])
        and isinstance(value["source_token_sha256"], str)
        and SHA256.fullmatch(value["source_token_sha256"]),
        "Invalid recovery identity",
    )
    public = value["host_public"]
    fixed = {
        "id": value["host_id"],
        "address": "198.18.241.2",
        "port": 22423,
        "username": "opsark-readonly",
        "site_domain": "defense.invalid",
        "container_name": "api",
        "expected_upstream_port": 8081,
        "source": "ssh",
        "health_checks": [],
        "nginx_config_path": None,
        "web_profile_digest": None,
    }
    require(
        isinstance(public, dict)
        and set(public) == {*fixed, "name", "trusted_hosts_digest"}
        and all(public[key] == item for key, item in fixed.items())
        and isinstance(public["name"], str)
        and 0 < len(public["name"]) <= 128,
        "The expected enrollment is outside the fixed isolated fixture",
    )
    known = value["known_hosts"]
    require(isinstance(known, str), "The expected host pin must be public text")
    match = re.fullmatch(r"\[198\.18\.241\.2\]:22423 ssh-ed25519 ([A-Za-z0-9+/]{68})\n", known)
    if match is None:
        raise RuntimeError("The expected public host pin is invalid")
    decoded = base64.b64decode(match[1], validate=True)
    require(
        decoded[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" and len(decoded) == 51,
        "The expected public host key is invalid",
    )
    known_sha = hashlib.sha256(known.encode("ascii")).hexdigest()
    require(
        public["trusted_hosts_digest"] == known_sha
        and value.get("known_hosts_sha256", known_sha) == known_sha,
        "The public host pin changed",
    )
    last, row = value["last_observed"], value["cache_row"]
    require(
        isinstance(last, dict)
        and set(last) == {"status", "remaining_ms", "observed_at"}
        and last["status"] == "active"
        and type(last["remaining_ms"]) is int
        and 1 <= last["remaining_ms"] <= 60000
        and isinstance(last["observed_at"], str),
        "The expected historical observation must be active",
    )
    require(
        isinstance(row, list)
        and len(row) == 6
        and row[0] == value["host_id"]
        and isinstance(row[1], str)
        and SHA256.fullmatch(row[1])
        and row[2:5] == [value["action_id"], "active", last["remaining_ms"]]
        and isinstance(row[5], str)
        and value.get("cache_row_sha256", compact_digest(row)) == compact_digest(row),
        "The expected observation row is invalid",
    )
    observed, saved = datetime.fromisoformat(last["observed_at"]), datetime.fromisoformat(row[5])
    require(
        observed.utcoffset() is not None and saved.utcoffset() is not None and observed == saved,
        "The historical observation timestamp differs",
    )
    scope = {key: item for key, item in public.items() if key not in {"name", "web_profile_digest"}}
    scope_sha = hashlib.sha256(
        json.dumps(
            scope,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    require(row[1] == scope_sha, "The historical observation scope differs")
    return value, hashlib.sha256(raw).hexdigest()


def offline_cache(directory, expected):
    uri = (directory / "security.sqlite3").as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        require(
            [list(row) for row in db.execute(QUERY)] == [expected["cache_row"]],
            "The restored scoped observation row differs",
        )


def new_enrollment(directory, expected):
    directory.mkdir(mode=0o700)
    restore.run(
        [
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(directory / "collector"),
        ],
        "Fresh synthetic collector generation",
    )
    (directory / "known_hosts").write_text(expected["known_hosts"], encoding="ascii")
    public = expected["host_public"]
    fields = (
        "id",
        "name",
        "address",
        "port",
        "username",
        "site_domain",
        "container_name",
        "expected_upstream_port",
    )
    inventory = (
        '[credentials.fixture]\nkey_file="collector"\nknown_hosts_file="known_hosts"\n'
        '[[hosts]]\ncredential="fixture"\n'
        + "".join(key + "=" + json.dumps(public[key], ensure_ascii=True) + "\n" for key in fields)
        + "ssh_defense_action_ids=["
        + json.dumps(expected["action_id"])
        + "]\n"
    )
    (directory / "inventory.toml").write_text(inventory, encoding="ascii")
    for path in directory.iterdir():
        path.chmod(0o600)
        os.chown(path, UID, UID)
    os.chown(directory, UID, UID)


def isolated_api(docker, recovered, credentials, image, expected):
    info = docker(
        "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
    )
    require(
        info.decode("ascii").split() in ([image, "null"], [image, "{}"]),
        "The recovery image must be pinned and declare no volumes",
    )
    container = (
        docker(
            "create",
            "--name",
            "opsark-defense-restore-" + secrets.token_hex(10),
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
            "--mount",
            f"type=bind,src={credentials},dst=/app/fixture-credentials,readonly",
            "--env",
            "OPSARK_DATA_DIR=/app/data",
            "--env",
            "OPSARK_AI_PROVIDER=openai",
            "--env",
            "OPSARK_INVENTORY=/app/fixture-credentials/inventory.toml",
            "--env",
            "OPSARK_OBSERVE_ENABLED=0",
            "--env",
            "OPSARK_WEB_OBSERVE_ENABLED=0",
            "--env",
            "OPSARK_VULNERABILITY_SCAN_ENABLED=0",
            *(item for key in EMPTY_ENV for item in ("--env", key + "=")),
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
        details = docker(
            "inspect",
            "--format",
            "{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} "
            "{{.Config.User}} {{json .HostConfig.PortBindings}} {{json .Mounts}}",
            container,
        )
        parts = details.decode("ascii").split(maxsplit=4)
        require(
            parts[:3] == ["none", "true", f"{UID}:{UID}"] and json.loads(parts[3]) in (None, {}),
            "The recovery controller is not isolated",
        )
        mounts = json.loads(parts[4])
        require(
            len(mounts) == 2
            and all(row["Type"] == "bind" for row in mounts)
            and {(row["Source"], row["Destination"], row["RW"]) for row in mounts}
            == {
                (str(recovered), "/app/data", True),
                (str(credentials), "/app/fixture-credentials", False),
            },
            "The recovery controller has unexpected mounts",
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
            if result.get("error") in {
                "api_size",
                "cache",
                "startup",
                "token",
                "auth",
                "registration",
                "ai",
                "history",
                "unavailable",
                "timestamp",
            }:
                raise RuntimeError(
                    "Defense recovery loopback proof failed (" + result["error"] + ")"
                )
            require(
                set(result) == {"token_sha256", "cache_rows"}
                and result["cache_rows"] == 1
                and SHA256.fullmatch(result["token_sha256"]),
                "Invalid loopback proof result",
            )
            return result

        docker("start", container)
        first = probe()
        docker("restart", "-t", "5", container)
        require(probe() == first, "The fresh controller identity changed across restart")
    finally:
        docker("rm", "-f", container)


def exercise(root, snapshot, expected_path, image):
    restore.validate_paths(root, snapshot, expected_path)
    expected, expected_sha = read_expected(expected_path)
    source = restore.transfer("verify", snapshot)
    hashes = restore.snapshot_hashes(snapshot, source)
    offline_cache(snapshot, expected)
    with TemporaryDirectory(prefix="ssh-defense-restore-", dir=root) as temporary:
        workspace = Path(temporary)
        recovered = workspace / "recovered"
        cloned = restore.transfer("rehearse", snapshot, recovered)
        require(
            restore.transfer("verify", recovered) == cloned
            and all(
                source[name][field] == cloned[name][field]
                for name in source
                for field in ("table_count", "row_count")
            ),
            "The independent copy did not verify",
        )
        offline_cache(recovered, expected)
        require(
            {path.name for path in recovered.iterdir()} == {*cloned, "manifest.json"},
            "Unexpected files accompanied the recovered databases",
        )
        (recovered / "manifest.json").unlink()
        for name in cloned:
            path = recovered / name
            path.chmod(0o600)
            os.chown(path, UID, UID)
        os.chown(recovered, UID, UID)
        credentials = workspace / "fresh-credentials"
        new_enrollment(credentials, expected)

        def docker(*args, payload=None):
            return restore.run(
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
                timeout=40,
            )

        isolated_api(docker, recovered, credentials, image, expected)
    require(
        restore.transfer("verify", snapshot) == source
        and restore.snapshot_hashes(snapshot, source) == hashes
        and restore.file_hash(expected_path) == expected_sha,
        "The cold source was changed",
    )
    return {
        "databases_verified": len(source),
        "historical_observations_verified": 1,
        "fresh_local_credential_generated": True,
        "fresh_access_token_created": True,
        "active_history_retained_with_original_observed_at": True,
        "offline_query_unavailable_without_cache_change": True,
        "restart_retained_history_and_scope": True,
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
        print(
            json.dumps(
                exercise(args.root, args.snapshot, args.expected, args.image), sort_keys=True
            )
        )
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
        RecursionError,
    ):
        print("The isolated SSH defense recovery fixture could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
