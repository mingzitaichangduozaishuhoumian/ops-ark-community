#!/usr/bin/python3 -I
"""Administrator-only CAS installer; modifies only the explicitly owned lab vhost."""

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

VHOST = Path("/etc/nginx/conf.d/opsark-vps-lab.conf")
FORMAT = Path("/etc/nginx/conf.d/00-opsark-web-observation.conf")
PROFILE = Path("/etc/opsark/web-observation.json")
READER = Path("/usr/local/libexec/opsark-web-read")
MARKER = Path("/etc/opsark/web-observation-owned.json")
OWNER = "opsark-web-observation/v1"
VHOST_MARKER = b"# OpsArk disposable VPS fixture v1: opsark-lab-api\n"
LEGACY_ACCESS = (
    b"    access_log syslog:server=unix:/dev/log,facility=local5,tag=opsark_web,severity=info "
    b"opsark_web_json;\n"
)
ACCESS = (
    b"    access_log syslog:server=unix:/dev/log,nohostname,facility=local5,tag=opsark_web,"
    b"severity=info opsark_web_json;\n"
)
SITE = b'    set $opsark_web_site "lab";\n'
DEFAULT_PROFILE = {
    "schema_version": 1,
    "sites": [
        {
            "id": "lab",
            "domain": "opsark-lab.invalid",
            "origin": "controlled_web_probe",
            "trusted_proxies": [],
            "forwarded_header": "x-forwarded-for",
            "expected_error_statuses": [],
        }
    ],
}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/root"}


class InstallError(ValueError):
    pass


def sha(value):
    return hashlib.sha256(value).hexdigest()


def parents(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError("untrusted_install_parent")


def trusted(path, *, limit=65536):
    parents(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise InstallError("untrusted_install_file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise InstallError("install_file_too_large")
    return data


def write(path, data, mode):
    parents(path.parent)
    if path.exists() or path.is_symlink():
        trusted(path)
    temp = path.with_name("." + path.name + ".opsark-web-" + str(os.getpid()))
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.chown(temp, 0, 0)
        os.replace(temp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def call(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10, env=ENV)  # noqa: S603 -- fixed reviewed administrator argv.


def load_marker():
    if not MARKER.exists() and not MARKER.is_symlink():
        return None
    value = json.loads(trusted(MARKER))
    if (
        not isinstance(value, dict)
        or set(value) != {"owner", "sha256", "backup", "profile_digest"}
        or value.get("owner") != OWNER
        or not isinstance(value.get("sha256"), dict)
        or set(value["sha256"]) != {str(path) for path in (FORMAT, PROFILE, READER, VHOST)}
        or any(
            not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in value["sha256"].values()
        )
        or not isinstance(value["profile_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["profile_digest"])
        or not isinstance(value["backup"], str)
        or not value["backup"].startswith("/root/opsark-web-backup-")
    ):
        raise InstallError("unrelated_ownership_marker")
    return value


def modified_vhost(content, owned, *, owned_vhost_digest=None):
    if (
        not content.startswith(VHOST_MARKER)
        or content.count(b"listen 127.0.0.1:18880;") != 1
        or content.count(b"server_name opsark-lab.invalid;") != 1
        or content.count(b"server {") != 1
        or content.count(b"    access_log ") != 1
    ):
        raise InstallError("refusing_unowned_vhost")
    if owned and owned_vhost_digest != sha(content):
        raise InstallError("owned_vhost_changed_review_required")
    if (
        owned
        and content.count(ACCESS) == 1
        and content.count(SITE) == 1
        and b"    access_log off;\n" not in content
    ):
        return content
    if (
        owned
        and content.count(LEGACY_ACCESS) == 1
        and content.count(SITE) == 1
        and ACCESS not in content
        and b"    access_log off;\n" not in content
    ):
        return content.replace(LEGACY_ACCESS, ACCESS)
    if content.count(b"    access_log off;\n") != 1 or b"$opsark_web_site" in content:
        raise InstallError("vhost_access_log_changed_review_required")
    return content.replace(b"    access_log off;\n", SITE + ACCESS)


def install(expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected or ""):
        raise InstallError("explicit_current_vhost_sha256_required")
    current = trusted(VHOST)
    if sha(current) != expected:
        raise InstallError("vhost_compare_and_swap_failed")
    marker = load_marker()
    targets = (FORMAT, PROFILE, READER)
    for path in targets:
        if path.exists() or path.is_symlink():
            content = trusted(path)
            if not marker or marker["sha256"].get(str(path)) != sha(content):
                raise InstallError("refusing_unowned_or_changed_install_file")
    version = call(["/usr/sbin/nginx", "-V"])
    if version.returncode != 0 or "--with-http_realip_module" not in version.stderr:
        raise InstallError("realip_peer_metadata_module_required")
    source = Path(__file__).resolve().parent
    helper = trusted(source / "read_journal.py").decode("utf-8").replace("\r\n", "\n").encode()
    log_format = (
        trusted(source / "nginx-format.conf").decode("utf-8").replace("\r\n", "\n").encode()
    )
    profile = (json.dumps(DEFAULT_PROFILE, sort_keys=True, separators=(",", ":")) + "\n").encode()
    updated = modified_vhost(
        current,
        bool(marker),
        owned_vhost_digest=marker["sha256"][str(VHOST)] if marker else None,
    )
    backup = Path("/root") / (
        "opsark-web-backup-"
        + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + "-"
        + str(os.getpid())
    )
    backup.mkdir(mode=0o700)
    snapshots = {path: trusted(path) if path.exists() else None for path in (*targets, VHOST)}
    for path, content in snapshots.items():
        if content is not None:
            write(backup / path.name, content, 0o600)
    written = {}
    reload_attempted = False
    try:
        write(FORMAT, log_format, 0o644)
        written[FORMAT] = log_format
        if sha(trusted(VHOST)) != expected:
            raise InstallError("vhost_changed_during_prepare")
        write(VHOST, updated, 0o644)
        written[VHOST] = updated
        if call(["/usr/sbin/nginx", "-t"]).returncode != 0:
            raise InstallError("nginx_syntax_failed")
        write(PROFILE, profile, 0o600)
        written[PROFILE] = profile
        write(READER, helper, 0o755)
        written[READER] = helper
        reload_attempted = True
        if call(["/usr/sbin/nginx", "-s", "reload"]).returncode != 0:
            raise InstallError("nginx_reload_failed")
    except Exception as error:
        try:
            conflict = any(sha(trusted(path)) != sha(content) for path, content in written.items())
        except (OSError, ValueError):
            conflict = True
        if conflict:
            raise InstallError("rollback_conflict_manual_review_required") from error
        for path in written:
            content = snapshots[path]
            if content is None:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            else:
                write(
                    path, content, 0o755 if path == READER else 0o600 if path == PROFILE else 0o644
                )
        if call(["/usr/sbin/nginx", "-t"]).returncode == 0 and reload_attempted:
            call(["/usr/sbin/nginx", "-s", "reload"])
        raise
    installed = {str(path): sha(trusted(path)) for path in (*targets, VHOST)}
    record = {
        "owner": OWNER,
        "sha256": installed,
        "backup": str(backup),
        "profile_digest": sha(profile),
    }
    write(MARKER, (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    return {
        "installed": True,
        "profile_digest": sha(profile),
        "vhost_sha256": sha(updated),
        "backup": str(backup),
        "only_lab_vhost_changed": True,
        "old_business_or_dns_changed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "status"))
    parser.add_argument("--expected-vhost-sha256")
    args = parser.parse_args()
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise InstallError("administrator_root_required")
        os.umask(0o077)
        if args.action == "install":
            result = install(args.expected_vhost_sha256)
        else:
            marker = load_marker()
            if marker is None:
                raise InstallError("not_installed")
            if any(sha(trusted(Path(path))) != digest for path, digest in marker["sha256"].items()):
                raise InstallError("installed_file_changed")
            result = {
                "installed": True,
                "profile_digest": marker["profile_digest"],
                "vhost_sha256": marker["sha256"][str(VHOST)],
            }
        print(json.dumps({"ok": True, **result}))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        code = (
            str(error)
            if isinstance(error, InstallError)
            else "web_observation_install_did_not_complete"
        )
        print(json.dumps({"ok": False, "error": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
