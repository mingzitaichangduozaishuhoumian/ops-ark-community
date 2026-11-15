"""Create bounded filesystem faults inside two verified disposable tmpfs mounts."""

import argparse
import errno
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/fixture-root")
STATE = Path("/fixture-state")
MARKER = STATE / "initialized.json"
PROOF = STATE / "holder.json"
PID = STATE / "holder.pid"
LOG = ROOT / "var/log/nginx/opsark-fill.log"
BUSINESS = ROOT / "srv/opsark-fill.data"
DELETED = ROOT / "srv/opsark-deleted.data"
INODES = ROOT / "var/lib/docker/containers/opsark-inodes"
APPLET_NAMES = (
    "sh",
    "env",
    "uname",
    "cat",
    "tail",
    "sha256sum",
    "test",
)
REQUIRED_APPLETS = {"sh", "env", "uname", "cat"}
NATIVE_NAMES = ("df", "nice", "du", "timeout")
WEB_NATIVE_NAMES = (*NATIVE_NAMES, "curl", "ss")
DIRECTORIES = (
    "bin",
    "dev",
    "etc",
    "proc",
    "srv",
    "var",
    "var/log",
    "var/log/nginx",
    "var/log/journal",
    "var/lib",
    "var/lib/docker",
    "var/lib/docker/containers",
    "var/lib/docker/containers/opsark-inodes",
)
ROOT_BYTES = 32 * 1024 * 1024
INODE_ROOT_BYTES = 2 * 1024 * 1024 * 1024
STATE_BYTES = 4 * 1024 * 1024
MAX_FILL = 30 * 1024 * 1024
SPARE = 2 * 1024 * 1024
BLOCK = b"F" * 65_536


def require(value):
    if not value:
        raise RuntimeError("The disposable filesystem fixture could not be verified")


def _mount(path, sizes, *, executable):
    entries = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        before, _, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if len(fields) >= 6 and fields[4] == str(path):
            entries.append((fields, filesystem))
    require(len(entries) == 1)
    fields, filesystem = entries[0]
    require(len(filesystem) == 3 and filesystem[0] == "tmpfs" and fields[3] == "/")
    options = fields[5].split(",")
    require(
        "rw" in options
        and "nodev" in options
        and "nosuid" in options
        and (not executable or "noexec" not in options)
    )
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    actual = os.statvfs(path)
    require(actual.f_blocks * actual.f_frsize in sizes)
    return info, actual


def validate():
    require(sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file())
    root, actual = _mount(ROOT, (ROOT_BYTES, INODE_ROOT_BYTES), executable=True)
    state, _ = _mount(STATE, (STATE_BYTES,), executable=False)
    require(actual.f_files == 256 and root.st_dev != state.st_dev)
    return root.st_dev


def _read(path, limit=4096):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and not info.st_mode & 0o022
            and 0 < info.st_size <= limit
        )
        data = handle.read(limit + 1)
        require(len(data) == info.st_size)
        return data


def _write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _inode_profile():
    return os.statvfs(ROOT).f_blocks * os.statvfs(ROOT).f_frsize == INODE_ROOT_BYTES


def _install_native(*, web_profile=False):
    names = WEB_NATIVE_NAMES if web_profile else NATIVE_NAMES
    sources = {Path("/usr/bin") / name for name in names}
    for name in names:
        result = subprocess.run(  # noqa: S603 -- fixed immutable tools and their executable libraries.
            ["/usr/bin/ldd", "/usr/bin/" + name],
            capture_output=True,
            timeout=3,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        require(result.returncode == 0 and len(result.stdout) <= 4096)
        dependencies = re.findall(rb"(?:=>\s+|^\s*)(/[^\s]+)\s+\(", result.stdout, re.MULTILINE)
        require(1 <= len(dependencies) <= (64 if web_profile else 8))
        for raw in dependencies:
            source = Path(os.fsdecode(raw))
            require(
                source.is_absolute()
                and ".." not in source.parts
                and re.fullmatch(
                    r"/(?:usr/lib|lib|lib64)/[A-Za-z0-9_./+-]+",
                    str(source),
                )
                is not None
            )
            sources.add(source)
    require(len(sources) <= (64 if web_profile else 27))
    fingerprints = {}
    total = 0
    for source in sorted(sources):
        data = _read(source.resolve(strict=True), 8 * 1024 * 1024)
        total += len(data)
        require(total <= (32 if web_profile else 8) * 1024 * 1024)
        relative = str(source)[1:]
        destination = ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        _write(destination, data, 0o755)
        fingerprints[relative] = _hash(data)
    for name in names:
        (ROOT / "bin" / name).symlink_to("../usr/bin/" + name)
    return fingerprints


def initialized(*, web_profile=None):
    device = validate()
    proof = json.loads(_read(MARKER, 16_384))
    require(
        set(proof)
        == {
            "device",
            "inode_profile",
            "web_profile",
            "busybox_sha256",
            "os_sha256",
            "native_files",
            "applets",
        }
        and proof["device"] == device
        and proof["inode_profile"] is _inode_profile()
        and type(proof["web_profile"]) is bool
        and (web_profile is None or proof["web_profile"] is web_profile)
        and (not proof["web_profile"] or _inode_profile())
    )
    require(
        _hash(_read(ROOT / "bin/busybox", 8 * 1024 * 1024)) == proof["busybox_sha256"]
        and _hash(_read(ROOT / "etc/os-release")) == proof["os_sha256"]
    )
    for name in DIRECTORIES:
        info = (ROOT / name).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_dev == device)
    applets = proof["applets"]
    required = REQUIRED_APPLETS | ({"tail"} if proof["web_profile"] else set())
    require(
        isinstance(applets, list)
        and len(applets) == len(set(applets))
        and required <= set(applets) <= set(APPLET_NAMES)
    )
    for name in APPLET_NAMES:
        path = ROOT / "bin" / name
        if name in applets:
            require(os.readlink(path) == "busybox")
        else:
            require(not path.exists() and not path.is_symlink())
    names = WEB_NATIVE_NAMES if proof["web_profile"] else NATIVE_NAMES
    native_paths = {"usr/bin/" + name for name in names}
    for name in names:
        require(os.readlink(ROOT / "bin" / name) == "../usr/bin/" + name)
    require(
        isinstance(proof["native_files"], dict)
        and set(proof["native_files"]) >= native_paths
        and 4 <= len(proof["native_files"]) <= (64 if proof["web_profile"] else 27)
    )
    for relative, fingerprint in proof["native_files"].items():
        require(
            relative in native_paths
            or re.fullmatch(
                r"(?:usr/lib|lib|lib64)/[A-Za-z0-9_./+-]+",
                relative,
            )
            is not None
        )
        require(
            ".." not in Path(relative).parts
            and _hash(
                _read(
                    ROOT / relative,
                    8 * 1024 * 1024,
                )
            )
            == fingerprint
        )
    require(_read(ROOT / "proc/mounts") == b"tmpfs / tmpfs rw,nosuid,nodev 0 0\n")
    require(os.readlink(ROOT / "etc/mtab") == "../proc/mounts")


def initialize(*, web_profile=False):
    device = validate()
    if MARKER.exists():
        initialized(web_profile=web_profile)
        return snapshot("initialize")
    require(not any(ROOT.iterdir()))
    busybox = _read(Path("/bin/busybox").resolve(strict=True), 8 * 1024 * 1024)
    # The exact public OS metadata is the only source configuration copied into the miniroot.
    release = Path("/etc/os-release").read_bytes()
    require(0 < len(release) <= 4096 and b"\x00" not in release)
    for name in DIRECTORIES:
        (ROOT / name).mkdir(mode=0o755)
    _write(ROOT / "bin/busybox", busybox, 0o755)
    result = subprocess.run(  # noqa: S603 -- copied static immutable BusyBox enumerates own applets.
        [str(ROOT / "bin/busybox"), "--list"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=2,
        check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= 16_384)
    available = set(result.stdout.decode("ascii").splitlines())
    require(available >= REQUIRED_APPLETS | ({"tail"} if web_profile else set()))
    applets = [name for name in APPLET_NAMES if name in available]
    for name in applets:
        (ROOT / "bin" / name).symlink_to("busybox")
    _write(ROOT / "etc/os-release", release, 0o644)
    # The fixed shell probe only redirects command discovery here, without device access.
    _write(ROOT / "dev/null", b"")
    # BusyBox reads this mount catalogue, then obtains every numeric value using statfs('/').
    _write(ROOT / "proc/mounts", b"tmpfs / tmpfs rw,nosuid,nodev 0 0\n", 0o644)
    (ROOT / "etc/mtab").symlink_to("../proc/mounts")
    result = subprocess.run(  # noqa: S603 -- fixed chroot and literal owned executable.
        ["/usr/sbin/chroot", str(ROOT), "/bin/busybox", "true"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=False,
    )
    require(result.returncode == 0)
    require(not web_profile or _inode_profile())
    native_files = _install_native(web_profile=web_profile)
    require(
        _inode_profile()
        or os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize >= (SPARE + 16 * 1024 * 1024)
    )
    _write(
        MARKER,
        json.dumps(
            {
                "device": device,
                "inode_profile": _inode_profile(),
                "web_profile": web_profile,
                "busybox_sha256": _hash(busybox),
                "os_sha256": _hash(release),
                "native_files": native_files,
                "applets": applets,
            },
            sort_keys=True,
        ).encode("ascii"),
    )
    return snapshot("initialize")


def _process_start(pid):
    return int(Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[19])


def _holder():
    if not PROOF.exists() and not PID.exists():
        return None
    proof = json.loads(_read(PROOF))
    require(
        set(proof) == {"pid", "start", "namespace", "fd", "device", "inode", "bytes"}
        and all(
            type(proof[key]) is int and proof[key] > 0
            for key in ("pid", "start", "fd", "device", "inode", "bytes")
        )
        and isinstance(proof["namespace"], list)
        and len(proof["namespace"]) == 2
        and _read(PID, 16) == (str(proof["pid"]) + "\n").encode("ascii")
        and 16 * 1024 * 1024 <= proof["bytes"] <= MAX_FILL
    )
    pid = proof["pid"]
    pidfd = os.pidfd_open(pid, 0)
    try:
        namespace = Path(f"/proc/{pid}/ns/mnt").stat()
        require(
            [namespace.st_dev, namespace.st_ino] == proof["namespace"]
            and os.path.samestat(namespace, Path("/proc/self/ns/mnt").stat())
            and _process_start(pid) == proof["start"]
            and Path(f"/proc/{pid}/exe").resolve() == Path(sys.executable).resolve()
            and Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")[:-1]
            == [
                os.fsencode(sys.executable),
                b"-I",
                b"-B",
                os.fsencode(Path(__file__).resolve()),
                b"_hold",
            ]
        )
        file = Path(f"/proc/{pid}/fd/{proof['fd']}")
        info = file.stat()
        require(
            os.readlink(file) == str(DELETED) + " (deleted)"
            and info.st_nlink == 0
            and (info.st_dev, info.st_ino, info.st_size)
            == (
                proof["device"],
                proof["inode"],
                proof["bytes"],
            )
        )
        return pidfd, proof["bytes"]
    except BaseException:
        os.close(pidfd)
        raise


def snapshot(mode, *, enospc=False):
    actual = os.statvfs(ROOT)
    holder = _holder()
    held = 0
    if holder is not None:
        descriptor, held = holder
        os.close(descriptor)
    return {
        "mode": mode,
        "bytes_total": actual.f_blocks * actual.f_frsize,
        "bytes_used": (actual.f_blocks - actual.f_bfree) * actual.f_frsize,
        "bytes_available": actual.f_bavail * actual.f_frsize,
        "inodes_total": actual.f_files,
        "inodes_free": actual.f_ffree,
        "enospc": enospc,
        "held_bytes": held,
    }


def _remove_owned(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and info.st_dev == ROOT.stat().st_dev
    )
    path.unlink()


def reset():
    initialized()
    holder = _holder()
    if holder is not None:
        descriptor, _ = holder
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            require(bool(select.select([descriptor], [], [], 3)[0]))
        finally:
            os.close(descriptor)
        PROOF.unlink()
        PID.unlink()
    for path in (LOG, BUSINESS, DELETED):
        _remove_owned(path)
    for number in range(512):
        _remove_owned(INODES / f"opsark-{number:03}")
    require(not any(INODES.iterdir()))
    return snapshot("reset")


def _fill(handle):
    total = 0
    enospc = False
    while total < MAX_FILL and os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize > SPARE:
        try:
            written = handle.write(BLOCK)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            enospc = True
            break
        require(written == len(BLOCK))
        total += written
    require(total >= 16 * 1024 * 1024)
    return total, enospc


def _hold():
    initialized()
    require(not _inode_profile())
    require(not PROOF.exists() and not PID.exists())
    with os.fdopen(
        os.open(DELETED, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600),
        "wb",
        buffering=0,
    ) as file:
        total, _ = _fill(file)
        info = os.fstat(file.fileno())
        require(info.st_size == total)
        DELETED.unlink()
        namespace = Path("/proc/self/ns/mnt").stat()
        _write(PID, (str(os.getpid()) + "\n").encode("ascii"))
        pending = STATE / ".holder.pending"
        _write(
            pending,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "start": _process_start(os.getpid()),
                    "namespace": [namespace.st_dev, namespace.st_ino],
                    "fd": file.fileno(),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "bytes": total,
                },
                sort_keys=True,
            ).encode("ascii"),
        )
        os.rename(pending, PROOF)
        while True:
            signal.pause()


def scenario(mode):
    reset()
    require(_inode_profile() is (mode == "inodes"))
    if mode == "deleted-open":
        child = subprocess.Popen(  # noqa: S603 -- exact owned helper and internal fixed mode.
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_hold"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            require(child.poll() is None)
            if PROOF.exists():
                result = snapshot(mode)
                require(result["held_bytes"] >= 16 * 1024 * 1024)
                return result
            time.sleep(0.02)
        child.terminate()
        child.wait(timeout=2)
        raise RuntimeError("The controlled deleted-file holder did not become ready")
    enospc = False
    if mode == "inodes":
        for number in range(512):
            try:
                _write(INODES / f"opsark-{number:03}", b"")
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                enospc = True
                break
        require(enospc and os.statvfs(ROOT).f_ffree <= 1)
    else:
        path = LOG if mode == "logs" else BUSINESS
        with os.fdopen(
            os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600),
            "wb",
            buffering=0,
        ) as file:
            _, enospc = _fill(file)
    return snapshot(mode, enospc=enospc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inode-profile", action="store_true")
    parser.add_argument("--web-profile", action="store_true")
    parser.add_argument(
        "mode",
        choices=("initialize", "state", "logs", "business", "deleted-open", "inodes", "reset"),
    )
    args = parser.parse_args()
    mode = args.mode
    try:
        validate()
        require(
            _inode_profile() is args.inode_profile
            and (not args.web_profile or args.inode_profile)
            and (not args.inode_profile or mode in {"initialize", "state", "inodes", "reset"})
        )
        if mode == "initialize":
            result = initialize(web_profile=args.web_profile)
        elif mode == "reset":
            initialized(web_profile=args.web_profile)
            result = reset()
        elif mode == "state":
            initialized(web_profile=args.web_profile)
            result = snapshot(mode)
        else:
            initialized(web_profile=args.web_profile)
            result = scenario(mode)
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
    ):
        print("The isolated filesystem fixture could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["_hold"]:
        _hold()
    else:
        raise SystemExit(main())
