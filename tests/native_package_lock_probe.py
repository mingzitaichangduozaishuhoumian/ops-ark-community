"""Run Root's native lock primitive with deployment's system Python, without APT.

This stdlib-only helper deliberately has no pytest/controller imports. Temporary
regular files replace the fixed package paths; only root ownership/directory trust
metadata is isolated for an unprivileged CI runner. The original core function and
fcntl module, constants, ABI, syscalls and independent POSIX-lock children stay real.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import select
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

CASES = (
    "external_download_lock",
    "unrelated_descriptor_close",
    "partial_acquisition_cleanup",
)


def runtime_diagnostics():
    import fcntl

    return {
        "executable": sys.executable,
        "python": platform.python_version(),
        "platform": sys.platform,
        "machine": platform.machine(),
        "fcntl_file": getattr(fcntl, "__file__", None),
        "fcntl_origin": fcntl.__spec__.origin,
        "ofd_setlk": getattr(fcntl, "F_OFD_SETLK", None),
        "ofd_getlk": getattr(fcntl, "F_OFD_GETLK", None),
        "posix_setlk": getattr(fcntl, "F_SETLK", None),
    }


def load_root_function(folder):
    source = Path(__file__).resolve().parents[1] / "deploy/vulnerability/core.py"
    spec = importlib.util.spec_from_file_location("native_probe_root_core", source)
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    paths = tuple(folder / f"native-lock-{i}" for i in range(4))
    for path in paths:
        path.write_bytes(b"")
        path.chmod(0o600)

    def trusted_metadata(value):
        return SimpleNamespace(
            st_uid=0,
            st_mode=value.st_mode,
            st_nlink=value.st_nlink,
            st_dev=value.st_dev,
            st_ino=value.st_ino,
        )

    class TemporaryLockPath:
        def __init__(self, value):
            self.path = Path(value)

        def __fspath__(self):
            return str(self.path)

        @property
        def parents(self):
            return self.path.parents

        def lstat(self):
            return trusted_metadata(self.path.lstat())

    # Keep the real os module for the children and descriptor-close assertion;
    # replacing only core's reference cannot contaminate global process modules.
    core.os = SimpleNamespace(
        open=os.open,
        close=os.close,
        fstat=lambda descriptor: trusted_metadata(os.fstat(descriptor)),
        uname=os.uname,
        O_RDWR=os.O_RDWR,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_CLOEXEC=os.O_CLOEXEC,
        O_NONBLOCK=os.O_NONBLOCK,
        SEEK_SET=os.SEEK_SET,
    )
    core.Path = TemporaryLockPath
    core.directory = lambda *_args, **_kwargs: None
    core.NATIVE_PACKAGE_LOCKS = tuple(str(path) for path in paths)
    return core, paths


@contextmanager
def external_posix_lock(path):
    code = (
        "import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_RDWR);"
        "fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);"
        "print('locked',flush=True);sys.stdin.readline();os.close(fd)"
    )
    process = subprocess.Popen(  # noqa: S603 -- static child code and temporary lock path.
        [sys.executable, "-I", "-c", code, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([process.stdout], [], [], 5)
        assert ready and process.stdout.readline().strip() == "locked", "POSIX child failed"
        yield
    finally:
        try:
            _stdout, stderr = process.communicate("\n", timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            raise
        assert process.returncode == 0, stderr


def posix_probe(path):
    code = """
import errno,fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
    fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except OSError as error:
    raise SystemExit(3 if error.errno in {errno.EACCES,errno.EAGAIN} else 5)
finally:
    os.close(fd)
"""
    result = subprocess.run(  # noqa: S603 -- static child code and temporary lock path.
        [sys.executable, "-I", "-c", code, str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode in {0, 3}, result.stderr.decode()
    return result.returncode


def require_busy(core):
    try:
        with core.native_package_locks():
            pass
    except core.Rejected as error:
        assert "busy" in str(error), str(error)
        return
    raise AssertionError("A conflicting native package lock allowed the action")


def run_case(case):
    with tempfile.TemporaryDirectory(prefix="opsark-native-lock-") as temporary:
        folder = Path(temporary)
        core, paths = load_root_function(folder)
        # Positive controls ensure an ABI/syscall/metadata error cannot be
        # mistaken for the expected busy rejection in either conflict case.
        with core.native_package_locks():
            pass
        if case == "external_download_lock":
            status = folder / "dpkg-status-fixture"
            status.write_bytes(b"Unchanged while an external manager downloads its archive.\n")
            digest = hashlib.sha256(status.read_bytes()).hexdigest()
            with external_posix_lock(paths[0]):
                assert hashlib.sha256(status.read_bytes()).hexdigest() == digest
                require_busy(core)
            assert posix_probe(paths[0]) == 0
        elif case == "unrelated_descriptor_close":
            with core.native_package_locks():
                descriptor = os.open(paths[0], os.O_RDWR)
                os.close(descriptor)
                assert posix_probe(paths[0]) == 3
            assert posix_probe(paths[0]) == 0
        elif case == "partial_acquisition_cleanup":
            with external_posix_lock(paths[-1]):
                require_busy(core)
                assert all(posix_probe(path) == 0 for path in paths[:-1])
        else:
            raise AssertionError("Unknown kernel probe case")
        with core.native_package_locks():
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--case", choices=CASES)
    action.add_argument("--all", action="store_true")
    action.add_argument("--diagnostics", action="store_true")
    args = parser.parse_args()
    result = {"runtime": runtime_diagnostics(), "cases": []}
    if not args.diagnostics:
        for case in CASES if args.all else (args.case,):
            run_case(case)
            result["cases"].append({"case": case, "passed": True})
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
