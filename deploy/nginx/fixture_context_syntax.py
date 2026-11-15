"""Check the reviewed Nginx fixture graph in a disposable container."""

import subprocess
from pathlib import Path

from deploy.nginx import config_snapshot, fixture_action, fixture_context

_RUNTIME = fixture_context.RUNTIME_MOUNT
_SITES = "/fixture-sites"
_STATE = "/run/opsark-nginx-live"
_TLS = "/fixture-tls"
_TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,mode=0700,uid=65534,gid=65534,size=2m"
_MOUNTS = tuple(f"{path}:{_TMPFS_OPTIONS}" for path in (_RUNTIME, _SITES, _STATE))


def _program(
    tls: fixture_context.TLSMaterial | None = None,
    *,
    tls_chain: fixture_context.TLSChainMaterial | None = None,
) -> str:
    # Only trusted, shipped fixture constants enter this program. Reviewed target bytes
    # travel separately on stdin. TLS material is opened by Nginx from the fixed mount.
    if tls_chain is not None:
        fixtures = fixture_context.CHAIN_FIXTURE_FILES
        tls_identity = {
            _TLS: tls_chain.directory,
            **{f"{_TLS}/{name}": identity for name, identity in tls_chain.files.items()},
        }
    elif tls is not None:
        fixtures = fixture_context.TLS_FIXTURE_FILES
        tls_identity = {
            _TLS: tls.directory,
            f"{_TLS}/cert.pem": tls.certificate,
            f"{_TLS}/key.pem": tls.key,
        }
    else:
        fixtures = fixture_context.FIXTURE_FILES
        tls_identity = {}
    target = f"{_SITES}/{fixture_action.TARGET_NAME}"
    return (
        f"fixtures = {dict(sorted(fixtures.items()))!r}\n"
        f"runtime = {_RUNTIME!r}\n"
        f"target = {target!r}\n"
        f"state = {_STATE!r}\n"
        f"tls_identity = {tls_identity!r}\n"
        + r"""
import os
import stat
import subprocess
import sys
from pathlib import Path

def check_tls():
    for name, expected in tls_identity.items():
        st = Path(name).lstat()
        kind = stat.S_ISDIR if name == "/fixture-tls" else stat.S_ISREG
        if not kind(st.st_mode):
            raise ValueError
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink != 1:
            raise ValueError
        identity = {
            "dev": st.st_dev, "ino": st.st_ino, "ctime_ns": st.st_ctime_ns,
            "mtime_ns": st.st_mtime_ns, "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
        }
        if identity != expected:
            raise ValueError

os.umask(0o077)
try:
    data = sys.stdin.buffer.read(1025)
    if not 0 < len(data) <= 1024:
        raise ValueError
    for name, content in fixtures.items():
        path = Path(runtime) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    Path(target).write_bytes(data)
    check_tls()
    result = subprocess.run(
        ['/usr/sbin/nginx', '-t', '-q', '-e', 'stderr', '-p', state,
         '-c', str(Path(runtime) / 'nginx.conf')],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=5, check=False,
    )
    check_tls()
except (OSError, ValueError, subprocess.SubprocessError):
    sys.exit(11)
sys.exit(0 if result.returncode == 0 else 10)
"""
    )


def _tls_context(directory: Path) -> fixture_context.RuntimeContext:
    if not isinstance(directory, Path) or directory.name != "tls":
        raise config_snapshot.SnapshotError("Invalid fixture TLS directory")
    policy = fixture_action.fixture_policy(directory.parent)
    if directory != policy.anchor / "tls":
        raise config_snapshot.SnapshotError("Invalid fixture TLS directory")
    context = fixture_context.verify_context(policy)
    if (context.tls is None) == (context.tls_chain is None):
        raise config_snapshot.SnapshotError("A sealed fixture TLS context is required")
    return context


def validate(data: bytes, image: str, *, tls_directory: Path | None = None) -> str:
    """Return the syntax result for the exact supported target or restore preimage."""
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= 1024
        or (data != fixture_action.ORIGINAL and not config_snapshot._FIXTURE.fullmatch(data))
    ):
        return "unsupported"
    try:
        config_snapshot._pinned_image(image)
        if tls_directory is not None:
            context = _tls_context(tls_directory)
            result = config_snapshot._docker_syntax(
                data,
                image,
                validator=_program(context.tls, tls_chain=context.tls_chain),
                extra_tmpfs=_MOUNTS,
                tls_directory=tls_directory,
            )
            return result if _tls_context(tls_directory) == context else "unavailable"
        return config_snapshot._docker_syntax(
            data, image, validator=_program(), extra_tmpfs=_MOUNTS
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
