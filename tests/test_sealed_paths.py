"""Native filesystem boundaries use owned fixtures, real ACLs, and real kernel handles."""

import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from functools import cache
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import _sealed_paths as paths  # noqa: E402 -- exact checkout for isolated pytest.
from tools import sealed_backup as sealed  # noqa: E402 -- exact checkout for isolated pytest.


@cache
def windows_owner_sid():
    if os.name != "nt":
        pytest.skip("Windows native identity query")
    system = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    result = subprocess.run(  # noqa: S603 -- fixed native identity query, no shell.
        [str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=False,
        timeout=5,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0
    sid = re.search(rb"S-1-5-(?:[0-9]+-)*[0-9]+", result.stdout)
    assert sid is not None
    return sid[0].decode("ascii")


def windows_fixture_acl(workspace, target, everyone=None):
    """Apply an exact DACL only to a new directory belonging to this fixture."""
    if os.name != "nt":
        pytest.skip("Windows native DACL operation")
    from ctypes import wintypes

    assert workspace.parent.resolve() == Path.home().resolve()
    assert workspace.name.startswith("opsark-sealed-paths-")
    assert target == workspace or target.is_relative_to(workspace)
    assert target.is_dir() and not target.is_symlink() and not target.is_junction()
    owner = windows_owner_sid()
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner})"
    if everyone is not None:
        assert type(everyone) is int and 0 < everyone <= 0xFFFFFFFF
        # This ACE affects this ancestor only; the leaf retains a private DACL.
        sddl += f"(A;;0x{everyone:08x};;;WD)"
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    api.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    api.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    api.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    api.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    descriptor = wintypes.LPVOID()
    assert api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    )
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = wintypes.LPVOID()
        assert api.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        )
        assert present.value and dacl.value
        assert (
            api.SetNamedSecurityInfoW(str(target), 1, 4 | 0x80000000, None, None, dacl, None) == 0
        )
    finally:
        kernel.LocalFree(descriptor)


@pytest.fixture
def owned_namespace():
    profile = Path.home().resolve()
    with tempfile.TemporaryDirectory(prefix="opsark-sealed-paths-", dir=profile) as temporary:
        root = Path(temporary)
        assert root.parent.resolve() == profile
        if os.name == "nt":
            windows_fixture_acl(root, root)
        else:
            root.chmod(0o700)
        ancestor = root / "ancestor"
        leaf = ancestor / "private-tools"
        ancestor.mkdir(mode=0o700)
        leaf.mkdir(mode=0o700)
        candidate = leaf / ("fixture.exe" if os.name == "nt" else "fixture")
        if os.name == "nt":
            windows_fixture_acl(root, ancestor)
            windows_fixture_acl(root, leaf)
            candidate.write_bytes(b"synthetic-file-never-executed-on-windows")
        else:
            source = shutil.which("true")
            assert source is not None
            shutil.copyfile(Path(source).resolve(), candidate)
            candidate.chmod(0o700)
        yield SimpleNamespace(root=root, ancestor=ancestor, leaf=leaf, candidate=candidate)


@pytest.mark.skipif(os.name != "nt", reason="Real Windows native DACL and sharing checks")
@pytest.mark.parametrize(
    "access",
    [0x00000040, 0x00000002, 0x00000100, 0x00040000, 0x00080000, 0x10000000],
    ids=[
        "delete-child",
        "write-data",
        "write-attributes",
        "write-dacl",
        "write-owner",
        "generic-all",
    ],
)
def test_windows_untrusted_ancestor_cannot_admit_native_execution(owned_namespace, access):
    c = owned_namespace
    windows_fixture_acl(c.root, c.ancestor, access)
    entered = False
    try:
        with pytest.raises(paths.PathError), paths.executable_namespace(c.candidate):
            entered = True
    finally:
        windows_fixture_acl(c.root, c.ancestor)
    assert not entered


@pytest.mark.skipif(os.name != "nt", reason="Real Windows native DACL and sharing checks")
def test_windows_peer_creation_is_allowed_but_held_ancestor_cannot_be_renamed(owned_namespace):
    c = owned_namespace
    renamed = c.root / "renamed-ancestor"
    windows_fixture_acl(c.root, c.ancestor, 0x00000004)
    try:
        with paths.executable_namespace(c.candidate) as admitted:
            assert admitted == c.candidate
            with pytest.raises(OSError) as error:
                c.ancestor.rename(renamed)
            assert getattr(error.value, "winerror", None) == 32
            assert c.ancestor.is_dir() and not renamed.exists()
        # The same operation succeeding afterwards distinguishes a held kernel
        # namespace handle from a refusal caused merely by filesystem permissions.
        c.ancestor.rename(renamed)
        renamed.rename(c.ancestor)
    finally:
        windows_fixture_acl(c.root, c.ancestor)


@pytest.mark.skipif(sys.platform != "linux", reason="Real Linux owner and inode checks")
@pytest.mark.parametrize("owner", ["current", "system"])
def test_linux_current_and_system_owned_readonly_executables_are_trusted(owned_namespace, owner):
    candidate = owned_namespace.candidate
    if owner == "system":
        source = shutil.which("true")
        assert source is not None
        candidate = Path(source).resolve()
        assert candidate.stat().st_uid == 0
    expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert paths.verify_executable(candidate, expected) == candidate


@pytest.mark.skipif(sys.platform != "linux", reason="Real Linux owner and inode checks")
@pytest.mark.parametrize("which", ["ancestor", "candidate"])
def test_linux_other_uid_is_rejected_before_admission(owned_namespace, which):
    if sys.platform != "linux":
        pytest.skip("Real Linux ownership mutation")
    if os.geteuid() != 0:
        pytest.skip("Changing a fixture owner requires actual CAP_CHOWN")
    c = owned_namespace
    target = getattr(c, which)
    original = target.stat()
    try:
        os.chown(target, 65534, original.st_gid)
    except PermissionError:
        pytest.skip("This root runtime does not have CAP_CHOWN")
    entered = False
    try:
        with pytest.raises(paths.PathError), paths.executable_namespace(c.candidate):
            entered = True
    finally:
        os.chown(target, original.st_uid, original.st_gid)
    assert not entered


@pytest.mark.skipif(sys.platform != "linux", reason="Real Linux owner and inode checks")
@pytest.mark.parametrize("mode", [0o770, 0o707], ids=["group-writable", "other-writable"])
def test_linux_writable_ancestor_is_rejected_before_admission(owned_namespace, mode):
    c = owned_namespace
    c.ancestor.chmod(mode)
    entered = False
    try:
        with pytest.raises(paths.PathError), paths.executable_namespace(c.candidate):
            entered = True
    finally:
        c.ancestor.chmod(0o700)
    assert not entered


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux /proc/self/fd execution")
def test_linux_native_execution_uses_original_inode_and_detects_path_replacement(owned_namespace):
    c = owned_namespace
    false = shutil.which("false")
    assert false is not None and Path("/proc/self/fd").is_dir()
    replacement = c.leaf / "replacement"
    shutil.copyfile(Path(false).resolve(), replacement)
    replacement.chmod(0o700)
    original_ran, path_control_failed = False, False
    # The post-call file verification must still refuse publication after a
    # replacement, even though executing the retained descriptor itself is safe.
    with (
        pytest.raises(paths.PathError),
        paths.executable_namespace(c.candidate),
        paths.held_file(c.candidate, 64 * 1024 * 1024, private=False) as held,
    ):
        inode = os.fstat(held.handle.fileno()).st_ino
        os.replace(replacement, c.candidate)
        assert c.candidate.stat().st_ino != inode
        assert (
            sealed._native(
                [str(c.candidate)],
                executable_handle=held.handle,
                consume=lambda stream: stream.read(1),
                timeout=5,
            )
            == b""
        )
        original_ran = True
        result = subprocess.run(  # noqa: S603 -- fixed copied /usr/bin/false, owned fixture only.
            [str(c.candidate)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 1 and not result.stdout and not result.stderr
        path_control_failed = True
    assert original_ran and path_control_failed
