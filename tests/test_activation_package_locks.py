"""Native OFD lease boundaries and Linux subprocess POSIX-lock contention; no APT changes."""

import errno
import json
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_patch_agent import remote as remote


def setup_native(remote, tmp_path, monkeypatch):
    # These unit cases isolate file trust and descriptor cleanup. The kernel
    # cases below run the actual Root function in the deployed system runtime.
    paths = tuple(tmp_path / f"native-lock-{i}" for i in range(4))
    for path in paths:
        path.write_bytes(b"")
        path.chmod(0o600)
    faults = {"owner": 0, "links": 1, "mode": stat.S_IFREG | 0o600, "busy": None, "inode_delta": 0}
    opened, closed, operations = {}, [], []

    def metadata(value, *, named_path=False):
        return SimpleNamespace(
            st_uid=faults["owner"],
            st_nlink=faults["links"],
            st_mode=faults["mode"],
            st_dev=value.st_dev,
            st_ino=value.st_ino + (faults["inode_delta"] if named_path else 0),
        )

    class NativePath:
        def __init__(self, value):
            self.path = Path(value)

        def __fspath__(self):
            return str(self.path)

        @property
        def parents(self):
            return self.path.parents

        def lstat(self):
            return metadata(self.path.lstat(), named_path=True)

    def open_file(path, flags):
        operations.append((str(Path(os.fspath(path))), flags))
        descriptor = os.open(path, flags)
        opened[descriptor] = path
        return descriptor

    def close_file(descriptor):
        closed.append(descriptor)
        os.close(descriptor)

    def fstat(descriptor):
        return metadata(os.fstat(descriptor))

    def lock(descriptor, operation, lease):
        assert operation == fake.F_OFD_SETLK
        assert struct.unpack("@hhqqi4x", lease) == (fake.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        if faults["busy"] == len(opened) - 1:
            raise OSError(errno.EAGAIN, "private-test-lock-diagnostic")
        return 0

    fake = SimpleNamespace(F_OFD_SETLK=37, F_WRLCK=1, fcntl=lock)
    monkeypatch.setattr(
        remote.core,
        "importlib",
        SimpleNamespace(import_module=lambda _name: fake),
    )
    native_os = SimpleNamespace(
        open=open_file,
        close=close_file,
        fstat=fstat,
        uname=lambda: SimpleNamespace(machine="x86_64"),
        O_RDWR=os.O_RDWR,
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        O_NONBLOCK=getattr(os, "O_NONBLOCK", 0),
        SEEK_SET=os.SEEK_SET,
    )
    monkeypatch.setattr(remote.core, "os", native_os)
    monkeypatch.setattr(remote.core, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(remote.core, "Path", NativePath)
    monkeypatch.setattr(remote.core, "NATIVE_PACKAGE_LOCKS", tuple(str(p) for p in paths))
    return SimpleNamespace(
        core=remote.core,
        paths=paths,
        faults=faults,
        opened=opened,
        closed=closed,
        operations=operations,
        fcntl=fake,
    )


@pytest.fixture
def native(remote, tmp_path, monkeypatch):
    return setup_native(remote, tmp_path, monkeypatch)


def test_fixed_existing_files_receive_nonblocking_write_ofd_locks_with_zero_pid(native):
    with native.core.native_package_locks():
        assert len(native.opened) == 4 and native.closed == []
        assert [path for path, _flags in native.operations] == [str(p) for p in native.paths]
        assert all(not flags & os.O_CREAT for _path, flags in native.operations)
        assert all(flags & os.O_RDWR for _path, flags in native.operations)
    assert native.closed == list(reversed(native.opened))


@pytest.mark.parametrize(
    "fault,value",
    [
        ("owner", 1000),
        ("links", 2),
        ("mode", stat.S_IFLNK | 0o600),
        ("mode", stat.S_IFREG | 0o666),
    ],
)
def test_untrusted_native_lock_file_never_reaches_the_service_body(native, fault, value):
    native.faults[fault] = value
    with (
        pytest.raises(native.core.Rejected, match="untrusted"),
        native.core.native_package_locks(),
    ):
        pytest.fail("No service action may cross this trust failure")
    assert set(native.closed) == set(native.opened)


@pytest.mark.parametrize("index", range(4))
def test_later_native_contention_releases_every_earlier_lease(native, index):
    native.faults["busy"] = index
    with (
        pytest.raises(native.core.Rejected, match="busy or its locks") as caught,
        native.core.native_package_locks(),
    ):
        pytest.fail("No service action while a native package operation holds a lock")
    assert len(native.opened) == index + 1
    assert set(native.closed) == set(native.opened)
    assert "private-test" not in str(caught.value)


def test_missing_native_lock_is_not_created(native):
    native.paths[2].unlink()
    with (
        pytest.raises(native.core.Rejected, match="unavailable"),
        native.core.native_package_locks(),
    ):
        pytest.fail("Missing lock evidence cannot mean a free package manager")
    assert not native.paths[2].exists() and set(native.closed) == set(native.opened)


def test_native_lease_rejects_changed_path_inode_before_reporting_completion(native):
    with (
        pytest.raises(native.core.Rejected, match="identity changed"),
        native.core.native_package_locks(),
    ):
        native.faults["inode_delta"] = 1
    assert set(native.closed) == set(native.opened)


def test_unknown_ofd_semantics_fail_closed_without_opening_lockfiles(native):
    del native.fcntl.F_OFD_SETLK
    with (
        pytest.raises(native.core.Rejected, match="semantics are unavailable"),
        native.core.native_package_locks(),
    ):
        pytest.fail("No fallback to process-associated locks")
    assert not native.opened


def system_kernel_case(case):
    # Root's systemd unit uses /usr/bin/python3, while portable controller Python
    # builds can omit F_OFD_SETLK at compile time. Never inject that constant or
    # skip a missing runtime/capability: the actual deployed function must pass.
    helper = Path(__file__).with_name("native_package_lock_probe.py")
    result = subprocess.run(  # noqa: S603 -- fixed runtime/helper and enumerated case names.
        ["/usr/bin/python3", "-I", str(helper), "--case", case],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["cases"] == [{"case": case, "passed": True}]
    assert evidence["runtime"]["executable"] == "/usr/bin/python3"
    assert isinstance(evidence["runtime"]["ofd_setlk"], int)


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux OFD/POSIX lock interaction")
def test_external_posix_download_lock_blocks_even_when_package_status_digest_is_unchanged():
    system_kernel_case("external_download_lock")


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux OFD/POSIX lock interaction")
def test_an_unrelated_descriptor_close_does_not_release_ofd_lease():
    system_kernel_case("unrelated_descriptor_close")


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux OFD/POSIX lock interaction")
def test_partial_ofd_acquisition_does_not_leave_the_earlier_package_locks_held():
    system_kernel_case("partial_acquisition_cleanup")
