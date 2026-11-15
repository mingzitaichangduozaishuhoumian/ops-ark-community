"""Private, identity-checked filesystem operations for offline encrypted handover."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
import re
import secrets
import stat
import sys
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class PathError(ValueError):
    """A path or filesystem permission could not be verified."""


def _require(condition: object) -> None:
    if not condition:
        raise PathError("The filesystem path or permissions could not be verified")


@dataclass(frozen=True)
class _Identity:
    values: tuple[int, ...]
    security: str


if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _READ_CONTROL = 0x00020000
    _DELETE = 0x00010000
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _BACKUP_SEMANTICS = 0x02000000
    _OPEN_REPARSE = 0x00200000
    _REPARSE = 0x400
    _DIRECTORY = 0x10
    _TRUSTED = {"S-1-5-18": "system", "S-1-5-32-544": "administrators"}
    _INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

    class _FileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME),
            ("written", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("revision", wintypes.BYTE),
            ("unused", wintypes.BYTE),
            ("size", wintypes.WORD),
            ("count", wintypes.WORD),
            ("unused2", wintypes.WORD),
        ]

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", wintypes.LPVOID),
            ("inherit", wintypes.BOOL),
        ]

    class _RenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace", wintypes.BYTE),
            ("parent", wintypes.HANDLE),
            ("length", wintypes.DWORD),
            ("name", wintypes.WCHAR * 1),
        ]

    _kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel.CreateFileW.restype = wintypes.HANDLE
    _kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel.CloseHandle.restype = wintypes.BOOL
    _kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    _kernel.CreateDirectoryW.restype = wintypes.BOOL
    _kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInfo)]
    _kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel.GetFileType.argtypes = [wintypes.HANDLE]
    _kernel.GetFileType.restype = wintypes.DWORD
    _kernel.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _kernel.GetVolumeInformationByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _kernel.GetVolumeInformationByHandleW.restype = wintypes.BOOL
    _kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _kernel.GetDriveTypeW.restype = wintypes.UINT
    _kernel.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel.LocalFree.restype = wintypes.HLOCAL
    _kernel.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    _advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi.OpenProcessToken.restype = wintypes.BOOL
    _advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi.GetTokenInformation.restype = wintypes.BOOL
    _advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    _advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _advapi.GetSecurityInfo.restype = wintypes.DWORD
    _advapi.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
    _advapi.GetAce.restype = wintypes.BOOL
    _advapi.IsValidSid.argtypes = [wintypes.LPVOID]
    _advapi.IsValidSid.restype = wintypes.BOOL
    _advapi.GetLengthSid.argtypes = [wintypes.LPVOID]
    _advapi.GetLengthSid.restype = wintypes.DWORD
    _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    def _sid(pointer: int | None) -> str:
        _require(isinstance(pointer, int) and bool(pointer) and _advapi.IsValidSid(pointer))
        output = wintypes.LPWSTR()
        _require(_advapi.ConvertSidToStringSidW(pointer, ctypes.byref(output)))
        try:
            value = output.value
            if value is None:
                raise PathError("The filesystem principal could not be verified")
            return value
        finally:
            _kernel.LocalFree(output)

    def _user_sid() -> str:
        token = wintypes.HANDLE()
        _require(_advapi.OpenProcessToken(_kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
        try:
            needed = wintypes.DWORD()
            _advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            _require(0 < needed.value <= 65536)
            buffer = ctypes.create_string_buffer(needed.value)
            _require(_advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)))
            return _sid(ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID)).contents.value)
        finally:
            _kernel.CloseHandle(token)

    def _win_security(
        handle: int, private: bool, directory: bool, namespace=False
    ) -> tuple[str, dict]:
        owner, dacl, descriptor = (wintypes.LPVOID() for _ in range(3))
        _require(
            _advapi.GetSecurityInfo(
                handle,
                1,
                5,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            == 0
        )
        try:
            own_sid = _user_sid()
            trusted = {**_TRUSTED, own_sid: "current_user"}
            if not private:
                trusted[_INSTALLER] = "trusted_installer"
            owner_sid = _sid(owner.value)
            _require(owner_sid in trusted and bool(dacl.value))
            acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
            _require(acl.revision in (2, 4) and 8 <= acl.size <= 65535 and acl.count <= 1024)
            # Directory namespace handles deny both write and delete sharing. An
            # explicit right to create a sibling directory is distinct from
            # replacing an existing child. Write-data/attributes can modify a
            # reparse point, so those rights remain forbidden for other SIDs.
            protected = (
                0x500D0152 if namespace else (0xF0000000 | 0x000D017F if private else 0x500D0156)
            )
            for index in range(acl.count):
                ace = wintypes.LPVOID()
                _require(_advapi.GetAce(dacl, index, ctypes.byref(ace)))
                address = ace.value
                start = dacl.value
                if address is None or start is None:
                    raise PathError("The filesystem permissions could not be verified")
                _require(start + 8 <= address <= start + acl.size - 4)
                header = ctypes.string_at(ace, 4)
                kind, flags = header[0], header[1]
                size = int.from_bytes(header[2:4], "little")
                _require(size >= 4 and address + size <= start + acl.size)
                if kind in (1, 6, 10, 12):
                    continue
                _require(kind in (0, 5) and size >= 12)
                raw = ctypes.string_at(ace, size)
                access = int.from_bytes(raw[4:8], "little")
                offset = 8
                if kind == 5:
                    ace_flags = int.from_bytes(raw[8:12], "little")
                    _require(not ace_flags & ~3)
                    offset = 12 + 16 * bool(ace_flags & 1) + 16 * bool(ace_flags & 2)
                _require(offset + 8 <= size)
                principal = _sid(address + offset)
                _require(offset + _advapi.GetLengthSid(address + offset) <= size)
                creator = principal == "S-1-3-0" and bool(flags & 8)
                owner_rights = principal == "S-1-3-4"
                ineffective = bool(flags & 8) and (not directory or namespace)
                _require(
                    principal in trusted
                    or owner_rights
                    or creator
                    or ineffective
                    or not access & protected
                )
            security = hashlib.sha256(
                owner_sid.encode() + ctypes.string_at(dacl, acl.size)
            ).hexdigest()
            return security, {
                "platform": "windows",
                "owner": trusted[owner_sid],
                "dacl": "restricted",
                "private": private,
                "filesystem": "NTFS_or_ReFS",
            }
        finally:
            _kernel.LocalFree(descriptor)

    def _win_open(
        path: Path, *, directory=False, write=False, delete=False, create=False, namespace=False
    ) -> int:
        access = (
            _GENERIC_READ
            | _READ_CONTROL
            | (_GENERIC_WRITE if write else 0)
            | (_DELETE if delete else 0)
        )
        security = wintypes.LPVOID()
        attributes = None
        if create:
            current = _user_sid()
            sddl = "O:" + current + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + current + ")"
            _require(
                _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, ctypes.byref(security), None
                )
            )
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), security, False)
        try:
            handle = _kernel.CreateFileW(
                "\\\\?\\" + str(path),
                access,
                7 if directory and not namespace else 1,
                ctypes.byref(attributes) if attributes is not None else None,
                1 if create else 3,
                _OPEN_REPARSE | (_BACKUP_SEMANTICS if directory else 0),
                None,
            )
            if handle == wintypes.HANDLE(-1).value:
                raise PathError("The filesystem entry could not be opened securely")
            return handle
        finally:
            if security.value:
                _kernel.LocalFree(security)

    def _win_mkdir(path: Path) -> None:
        current = _user_sid()
        sddl = "O:" + current + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + current + ")"
        security = wintypes.LPVOID()
        _require(
            _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(security), None
            )
        )
        try:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), security, False)
            _require(_kernel.CreateDirectoryW("\\\\?\\" + str(path), ctypes.byref(attributes)))
        finally:
            _kernel.LocalFree(security)

    def _win_snapshot(
        path: Path, handle: int, *, private=True, directory=False, namespace=False
    ) -> tuple[_Identity, dict]:
        info = _FileInfo()
        _require(
            _kernel.GetFileType(handle) == 1
            and _kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
        )
        _require(not info.attributes & _REPARSE and bool(info.attributes & _DIRECTORY) == directory)
        _require(directory or info.links == 1)
        filesystem = ctypes.create_unicode_buffer(32)
        flags = wintypes.DWORD()
        _require(
            _kernel.GetVolumeInformationByHandleW(
                handle, None, 0, None, None, ctypes.byref(flags), filesystem, len(filesystem)
            )
        )
        _require(
            filesystem.value.upper() in {"NTFS", "REFS"}
            and flags.value & 8
            and _kernel.GetDriveTypeW(path.anchor) == 3
        )
        final = ctypes.create_unicode_buffer(32768)
        length = _kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        _require(0 < length < len(final))
        name = final.value.removeprefix("\\\\?\\")
        _require(name.casefold() == str(path).casefold())
        security, permissions = _win_security(handle, private, directory, namespace)
        permissions["filesystem"] = filesystem.value
        values = (
            info.volume,
            info.index_high << 32 | info.index_low,
            info.attributes,
            info.links,
            info.size_high << 32 | info.size_low,
            info.written.dwHighDateTime << 32 | info.written.dwLowDateTime,
            info.created.dwHighDateTime << 32 | info.created.dwLowDateTime,
        )
        return _Identity(values, security), permissions


def _plain(path: Path, *, missing=False) -> Path:
    path = Path(path)
    _require(path.is_absolute() and ".." not in path.parts)
    if os.name == "nt":
        _require(bool(re.fullmatch(r"[A-Za-z]:", path.drive)))
        _require(all(":" not in part for part in path.parts[1:]))
        _require(
            all(
                not part.endswith((" ", "."))
                and not re.search(r'[<>"|?*\x00-\x1f]', part)
                and part.split(".", 1)[0].upper()
                not in {
                    "CON",
                    "PRN",
                    "AUX",
                    "NUL",
                    *("COM" + str(i) for i in range(1, 10)),
                    *("LPT" + str(i) for i in range(1, 10)),
                }
                for part in path.parts[1:]
            )
        )
    else:
        _require(sys.platform == "linux" and path.anchor == "/")
    for entry in (path.parent, *path.parent.parents) if missing else (path, *path.parents):
        info = entry.lstat()
        _require(
            not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400
        )
    return path


def _posix_snapshot(
    info: os.stat_result, *, private: bool, directory=False
) -> tuple[_Identity, dict]:
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    _require(directory or info.st_nlink == 1)
    _require(not info.st_mode & (0o077 if private else 0o022))
    if private:
        _require(sys.platform == "linux")
        if sys.platform == "linux":
            _require(info.st_uid == os.geteuid())
    values = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        info.st_gid,
    )
    return _Identity(values, ""), {
        "platform": "posix",
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


@contextlib.contextmanager
def _directory(
    path: Path, *, private=True, write=False, delete=False, namespace=False
) -> Generator[tuple[int, _Identity]]:
    path = _plain(path)
    if os.name == "nt":
        handle = _win_open(path, directory=True, write=write, delete=delete, namespace=namespace)
        try:
            identity, _ = _win_snapshot(
                path, handle, private=private, directory=True, namespace=namespace
            )
            yield handle, identity
        finally:
            _kernel.CloseHandle(handle)
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            identity, _ = _posix_snapshot(os.fstat(descriptor), private=private, directory=True)
            _require(os.path.samestat(path.lstat(), os.fstat(descriptor)))
            yield descriptor, identity
        finally:
            os.close(descriptor)


def private_directory(path: Path) -> Path:
    try:
        with _directory(path):
            return Path(path)
    except OSError:
        raise PathError("The private directory could not be verified") from None


@dataclass
class HeldFile:
    path: Path
    handle: BinaryIO
    identity: _Identity
    permissions: dict
    size: int
    private: bool

    def verify(self) -> None:
        try:
            _plain(self.path)
            if os.name == "nt":
                native = msvcrt.get_osfhandle(self.handle.fileno())
                held, _ = _win_snapshot(self.path, native, private=self.private)
                with _native_read(self.path, private=self.private) as (other, _):
                    current, _ = _win_snapshot(self.path, other, private=self.private)
            else:
                held, _ = _posix_snapshot(os.fstat(self.handle.fileno()), private=self.private)
                current, _ = _posix_snapshot(self.path.lstat(), private=self.private)
            _require(held == current == self.identity)
        except OSError:
            raise PathError("The held file changed or could not be verified") from None


@contextlib.contextmanager
def _native_read(path: Path, *, private=True, delete=False) -> Generator[tuple[int, _Identity]]:
    handle = _win_open(path, delete=delete)
    try:
        identity, _ = _win_snapshot(path, handle, private=private)
        yield handle, identity
    finally:
        _kernel.CloseHandle(handle)


@contextlib.contextmanager
def held_file(path: Path, limit: int, private=True) -> Generator[HeldFile]:
    try:
        path = _plain(path)
        _require(type(limit) is int and 0 <= limit <= 2**63 - 1)
        with _directory(path.parent, private=private):
            if os.name == "nt":
                native = _win_open(path)
                try:
                    identity, permissions = _win_snapshot(path, native, private=private)
                    descriptor = msvcrt.open_osfhandle(native, os.O_RDONLY | os.O_BINARY)
                except BaseException:
                    _kernel.CloseHandle(native)
                    raise
            else:
                descriptor = os.open(
                    path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                )
                try:
                    identity, permissions = _posix_snapshot(os.fstat(descriptor), private=private)
                except BaseException:
                    os.close(descriptor)
                    raise
            with os.fdopen(descriptor, "rb") as handle:
                size = os.fstat(handle.fileno()).st_size
                _require(size <= limit)
                result = HeldFile(path, handle, identity, permissions, size, private)
                result.verify()
                yield result
                result.verify()
    except OSError:
        raise PathError("The bounded file could not be read securely") from None


@contextlib.contextmanager
def new_file(path: Path) -> Generator[BinaryIO]:
    path = validate_destination(path)
    try:
        with _directory(path.parent) as (parent, parent_identity):
            if os.name == "nt":
                native = _win_open(path, write=True, create=True)
                try:
                    descriptor = msvcrt.open_osfhandle(native, os.O_RDWR | os.O_BINARY)
                except BaseException:
                    _kernel.CloseHandle(native)
                    raise
            else:
                descriptor = os.open(
                    path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
                )
            with os.fdopen(descriptor, "w+b") as handle:
                before = os.fstat(handle.fileno())
                yield handle
                handle.flush()
                os.fsync(handle.fileno())
                after = os.fstat(handle.fileno())
                _require(os.path.samestat(before, after) and os.path.samestat(path.lstat(), after))
                if os.name == "nt":
                    _win_snapshot(path, msvcrt.get_osfhandle(handle.fileno()))
                else:
                    _posix_snapshot(after, private=True)
            _same_directory(path.parent, parent, parent_identity)
    except OSError:
        raise PathError("The exclusive private output could not be created") from None


def validate_destination(path: Path) -> Path:
    try:
        path = _plain(path, missing=True)
        _require(not path.exists() and not path.is_symlink())
        private_directory(path.parent)
        return path
    except OSError:
        raise PathError("The new private destination could not be verified") from None


def _same_directory(path: Path, descriptor: int, identity: _Identity) -> None:
    if os.name == "nt":
        current, _ = _win_snapshot(path, descriptor, directory=True)
        _require(
            current.values[:2] == identity.values[:2] and current.security == identity.security
        )
    else:
        current, _ = _posix_snapshot(os.fstat(descriptor), private=True, directory=True)
        _require(
            current.values[:3] == identity.values[:3]
            and os.path.samestat(path.lstat(), os.fstat(descriptor))
        )


def _owned_tree(path: Path, *, depth=0, budget=None, device=None) -> None:
    if budget is None:
        budget = [512]
    _require(depth <= 8)
    with _directory(path) as (descriptor, identity):
        if device is None:
            device = identity.values[0]
        _require(identity.values[0] == device)
        for child in path.iterdir():
            budget[0] -= 1
            _require(budget[0] >= 0)
            info = child.lstat()
            _require(
                not stat.S_ISLNK(info.st_mode)
                and not getattr(info, "st_file_attributes", 0) & 0x400
            )
            if stat.S_ISDIR(info.st_mode):
                _owned_tree(child, depth=depth + 1, budget=budget, device=device)
            else:
                with held_file(child, 2**63 - 1):
                    pass
        _same_directory(path, descriptor, identity)


def _publish(staged: Path, destination: Path, *, directory: bool) -> None:
    staged = _plain(staged)
    destination = validate_destination(destination)
    _require(staged != destination and not destination.is_relative_to(staged))
    if directory:
        _owned_tree(staged)
    with (
        _directory(staged.parent) as (source_parent, source_identity),
        _directory(destination.parent) as (target_parent, target_identity),
    ):
        _require(source_identity.values[0] == target_identity.values[0])
        if os.name == "nt":
            handle = _win_open(staged, directory=directory, delete=True)
            try:
                _win_snapshot(staged, handle, directory=directory)
                encoded = ("\\\\?\\" + str(destination)).encode("utf-16-le")
                buffer = ctypes.create_string_buffer(_RenameInfo.name.offset + len(encoded) + 2)
                value = ctypes.cast(buffer, ctypes.POINTER(_RenameInfo)).contents
                value.replace, value.parent, value.length = False, None, len(encoded)
                ctypes.memmove(
                    ctypes.addressof(buffer) + _RenameInfo.name.offset, encoded, len(encoded)
                )
                _require(_kernel.SetFileInformationByHandle(handle, 3, buffer, len(buffer)))
                _win_snapshot(destination, handle, directory=directory)
            finally:
                _kernel.CloseHandle(handle)
        else:
            before = staged.lstat()
            _posix_snapshot(before, private=True, directory=directory)
            library = ctypes.CDLL(None, use_errno=True)
            operation = getattr(library, "renameat2", None)
            _require(operation is not None)
            operation.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            operation.restype = ctypes.c_int
            _require(
                operation(
                    source_parent,
                    os.fsencode(staged.name),
                    target_parent,
                    os.fsencode(destination.name),
                    1,
                )
                == 0
            )
            _require(os.path.samestat(before, destination.lstat()))
            os.fsync(source_parent)
            os.fsync(target_parent)
        _same_directory(staged.parent, source_parent, source_identity)
        _same_directory(destination.parent, target_parent, target_identity)


def publish_file(staged: Path, destination: Path) -> None:
    try:
        _publish(staged, destination, directory=False)
    except OSError:
        raise PathError("The private file could not be published without replacement") from None


def publish_directory(staged: Path, destination: Path) -> None:
    try:
        _publish(staged, destination, directory=True)
    except OSError:
        raise PathError(
            "The private directory could not be published without replacement"
        ) from None


def _cleanup(path: Path, descriptor: int, identity: _Identity) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    _same_directory(path, descriptor, identity)
    _owned_tree(path)
    for child in path.iterdir():
        if child.is_dir():
            with _directory(child, delete=True) as (nested, expected):
                _cleanup(child, nested, expected)
        elif os.name == "nt":
            with _native_read(child, delete=True) as (handle, _):
                remove = wintypes.BYTE(True)
                _require(_kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(remove), 1))
        else:
            opened = os.open(
                child.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(opened)
                _posix_snapshot(before, private=True)
                _require(os.path.samestat(before, child.lstat()))
                os.unlink(child.name, dir_fd=descriptor)
            finally:
                os.close(opened)
    _same_directory(path, descriptor, identity)
    if os.name == "nt":
        remove = wintypes.BYTE(True)
        _require(_kernel.SetFileInformationByHandle(descriptor, 4, ctypes.byref(remove), 1))
    else:
        path.rmdir()


@contextlib.contextmanager
def new_workspace(parent: Path, prefix: str) -> Generator[Path]:
    _require(
        isinstance(prefix, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,47}", prefix))
    )
    parent = private_directory(parent)
    path = parent / (prefix + "-" + secrets.token_hex(16))
    try:
        with _directory(parent):
            if os.name == "nt":
                _win_mkdir(path)
            else:
                path.mkdir(mode=0o700)
        with _directory(path, delete=True) as (descriptor, identity):
            try:
                yield path
            finally:
                _cleanup(path, descriptor, identity)
    except OSError:
        raise PathError("The owned private workspace could not be managed securely") from None


@contextlib.contextmanager
def executable_namespace(path: Path) -> Generator[Path]:
    """Hold the verified executable ancestry until the caller's last native call."""
    try:
        path = _plain(path)
        _require(len(path.parents) <= 64)
        with contextlib.ExitStack() as stack:
            held = []
            for parent in reversed(path.parents):
                if sys.platform == "linux":
                    info = parent.lstat()
                    _require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022)
                descriptor, identity = stack.enter_context(
                    _directory(parent, private=False, namespace=True)
                )
                held.append((parent, descriptor, identity))
            if sys.platform == "linux":
                info = path.lstat()
                _require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022)
            yield path
            for parent, descriptor, identity in held:
                if os.name == "nt":
                    current, _ = _win_snapshot(
                        parent, descriptor, private=False, directory=True, namespace=True
                    )
                    _require(
                        current.values[:2] == identity.values[:2]
                        and current.security == identity.security
                    )
                else:
                    info = os.fstat(descriptor)
                    current, _ = _posix_snapshot(info, private=False, directory=True)
                    _require(
                        current.values[:3] == identity.values[:3]
                        and current.values[-2:] == identity.values[-2:]
                        and os.path.samestat(info, parent.lstat())
                    )
    except OSError:
        raise PathError("The native executable namespace could not be verified") from None


def verify_executable(path: Path, expected_sha256: str) -> Path:
    _require(
        isinstance(expected_sha256, str) and bool(re.fullmatch(r"[0-9a-f]{64}", expected_sha256))
    )
    with executable_namespace(path), held_file(path, 64 * 1024 * 1024, private=False) as source:
        digest = hashlib.sha256()
        while chunk := source.handle.read(1024 * 1024):
            digest.update(chunk)
        _require(source.size > 0 and digest.hexdigest() == expected_sha256)
        if os.name != "nt":
            _require(bool(source.path.stat().st_mode & 0o111))
        source.verify()
    return Path(path)
