#!/usr/bin/python3 -I
"""Project a bounded Nginx error-log window without returning log bytes."""

import ipaddress
import json
import os
import re
import signal
import stat
import sys
import time
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "opsark-nginx-error-window/v1"
WINDOW_SECONDS = 900
MAX_BYTES = 128 * 1024
MAX_ROWS = 512
MAX_LINE = 8192
MAX_ZONE = 4096
LOG = Path("/var/log/nginx/error.log")
LOCAL_ZONE = Path("/etc/localtime")
UTC_ZONE = Path("/usr/share/zoneinfo/Etc/UTC")
ACCOUNT = "opsark-readonly"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ROW = re.compile(
    rb"([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) "
    rb"\[(?:emerg|alert|crit|error|warn|notice|info|debug)\] "
    rb"[0-9]{1,10}#[0-9]{1,20}: (?:\*[0-9]{1,20} )?([\x20-\x7e\x80-\xff]+)\Z"
)
_HTTP_CONTEXT = (
    rb"client: ([0-9a-fA-F:.]{1,80}), server: ([^,]{1,253}), "
    rb'request: "[^"\r\n]{1,4096}", upstream: "(?:http|https)://[^"\r\n]{1,2048}"'
    rb'(?:, host: "[^"\r\n]{1,253}")?(?:, referrer: "[^"\r\n]{0,1024}")?\Z'
)
_REFUSED = re.compile(
    rb"connect\(\) failed \(111: Connection refused\) while connecting to upstream, "
    + _HTTP_CONTEXT
)
_TIMEOUT = re.compile(
    rb"upstream timed out \(110: Connection timed out\) while "
    rb"(?:connecting to upstream|sending request to upstream|reading response header from upstream|"
    rb"reading upstream|reading upstream response body), " + _HTTP_CONTEXT
)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class Refused(ValueError):
    """Only fixed, non-sensitive reason codes are exposed."""


class Missing(ValueError):
    """The fixed source was absent at both trusted path observations."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def domain(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 253
        and all(_LABEL.fullmatch(part) for part in value.split("."))
    )


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_ctime_ns,
        info.st_mtime_ns,
    )


def directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_ctime_ns


def trusted(info, *, directory=False):
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    return kind and info.st_uid == 0 and not info.st_mode & 0o022


@contextmanager
def parent_chain(path):
    """Walk from / by open directories and verify original names before accepting."""
    flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_PATH
    parents = []
    with ExitStack() as close:
        current = os.open("/", flags)
        close.callback(os.close, current)
        root_fd = current
        root = os.fstat(root_fd)
        require(trusted(root, directory=True), "source_untrusted")
        for part in path.parts[1:-1]:
            try:
                before = os.stat(part, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError as error:
                # An absent ancestor does not prove a stable, admitted file location.
                raise Refused("coverage_unconfirmed") from error
            require(trusted(before, directory=True), "source_untrusted")
            child = os.open(part, flags, dir_fd=current)
            close.callback(os.close, child)
            token = directory_identity(before)
            require(directory_identity(os.fstat(child)) == token, "source_changed")
            parents.append((current, part, child, token))
            current = child

        def stable():
            try:
                require(
                    directory_identity(os.fstat(root_fd)) == directory_identity(root),
                    "source_changed",
                )
                for descriptor, name, child, expected in parents:
                    current_info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    require(
                        directory_identity(current_info)
                        == directory_identity(os.fstat(child))
                        == expected,
                        "source_changed",
                    )
            except FileNotFoundError as error:
                raise Refused("source_changed") from error

        chain = (directory_identity(root), *(entry[3] for entry in parents))
        yield current, stable, chain


def read_regular(path, maximum, *, single_link=True):
    with parent_chain(path) as (parent, stable, chain):
        try:
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            stable()
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError as error:
                stable()
                raise Missing from error
            raise Refused("source_changed") from None
        require(trusted(before) and (not single_link or before.st_nlink == 1), "source_untrusted")
        # Open even an empty file first so an existing unreadable source cannot
        # be mislabeled as an empty readable window.
        try:
            fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
            )
        except PermissionError:
            try:
                denied_file = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError as error:
                raise Refused("source_changed") from error
            require(identity(denied_file) == identity(before), "source_changed")
            stable()
            raise
        except FileNotFoundError as error:
            raise Refused("source_changed") from error
        with os.fdopen(fd, "rb") as stream:
            expected = identity(before)
            require(identity(os.fstat(stream.fileno())) == expected, "source_changed")
            require(before.st_size <= maximum, "coverage_unconfirmed")
            raw = stream.read(maximum + 1)
            require(
                len(raw) == before.st_size and identity(os.fstat(stream.fileno())) == expected,
                "source_changed",
            )
        try:
            require(
                identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == expected,
                "source_changed",
            )
        except FileNotFoundError as error:
            raise Refused("source_changed") from error
        stable()
        return raw, (expected, chain)


def check_current_log(expected):
    """Recheck the same fixed source after parsing and the second UTC observation."""
    with parent_chain(LOG) as (parent, stable, chain):
        try:
            current = os.stat(LOG.name, dir_fd=parent, follow_symlinks=False)
        except (FileNotFoundError, PermissionError) as error:
            raise Refused("source_changed") from error
        require((identity(current), chain) == expected, "source_changed")
        stable()


def utc_profile():
    try:
        require("TZ" not in os.environ, "clock_unconfirmed")
        before = LOCAL_ZONE.lstat()
        require(
            before.st_uid == 0 and (stat.S_ISLNK(before.st_mode) or trusted(before)),
            "clock_unconfirmed",
        )
        target = LOCAL_ZONE.resolve(strict=True)
        require(target in {LOCAL_ZONE, UTC_ZONE}, "clock_unconfirmed")
        reference, reference_id = read_regular(UTC_ZONE, MAX_ZONE, single_link=False)
        candidate, candidate_id = (
            (reference, reference_id)
            if target == UTC_ZONE
            else read_regular(LOCAL_ZONE, MAX_ZONE, single_link=False)
        )
        require(
            reference.startswith(b"TZif")
            and reference.endswith(b"\nUTC0\n")
            and candidate == reference
            and identity(LOCAL_ZONE.lstat()) == identity(before),
            "clock_unconfirmed",
        )
        return identity(before), candidate_id, reference_id
    except (OSError, RuntimeError, Refused, Missing) as error:
        raise Refused("clock_unconfirmed") from error


def timestamp(raw):
    try:
        text = raw.decode("ascii")
        value = datetime(
            int(text[:4]),
            int(text[5:7]),
            int(text[8:10]),
            int(text[11:13]),
            int(text[14:16]),
            int(text[17:19]),
            tzinfo=UTC,
        )
    except ValueError as error:
        raise Refused("coverage_unconfirmed") from error
    age = value - _EPOCH
    return age.days * 86400 + age.seconds


def event(message, expected):
    # Inspect the leading event phrase only. A request or host value farther
    # into an unrelated log record cannot become an upstream event marker.
    prefix = message.split(b", client: ", 1)[0]
    if b"Connection refused" in prefix and prefix.startswith(b"connect() failed"):
        matched = _REFUSED.match(message)
        label = "refused"
    elif prefix.startswith(b"upstream timed out"):
        matched = _TIMEOUT.match(message)
        label = "timeout"
    else:
        return None
    if matched is None:
        raise Refused("coverage_unconfirmed")
    try:
        ipaddress.ip_address(matched[1].decode("ascii"))
        server = matched[2].decode("ascii").lower().removesuffix(".")
    except ValueError as error:
        raise Refused("coverage_unconfirmed") from error
    require(domain(server), "coverage_unconfirmed")
    return label if server == expected else None


def project(raw, expected, observed):
    require(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "coverage_unconfirmed")
    rows = raw[:-1].split(b"\n")
    require(1 <= len(rows) <= MAX_ROWS, "coverage_unconfirmed")
    cutoff = observed - WINDOW_SECONDS
    previous = None
    anchored = False
    counts = {"refused": 0, "timeout": 0}
    for row in rows:
        require(0 < len(row) <= MAX_LINE, "coverage_unconfirmed")
        match = _ROW.fullmatch(row)
        if match is None:
            raise Refused("coverage_unconfirmed")
        instant = timestamp(match[1])
        require(
            instant <= observed and (previous is None or previous <= instant),
            "coverage_unconfirmed",
        )
        previous = instant
        if instant < cutoff:
            anchored = True
            continue
        label = event(match[2], expected)
        if label is not None:
            counts[label] += 1
    require(anchored, "coverage_unconfirmed")
    return counts


def drop_privileges():
    import pwd

    user = pwd.getpwnam(ACCOUNT)
    uid, gid = user.pw_uid, user.pw_gid
    require(uid > 0 and gid > 0, "source_untrusted")
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    require(
        os.getresuid() == (uid, uid, uid)
        and os.getresgid() == (gid, gid, gid)
        and set(os.getgroups()) <= {gid},
        "source_untrusted",
    )
    # Retained capabilities or ambient DAC override would undermine the
    # permission observation even when the numeric UID matches.
    with Path("/proc/self/status").open("rb") as stream:
        data = stream.read(16385)
    fields = re.findall(rb"^Cap(?:Eff|Prm|Amb):\s*([0-9a-f]+)$", data, re.MULTILINE)
    require(
        len(data) <= 16384 and len(fields) == 3 and all(int(x, 16) == 0 for x in fields),
        "source_untrusted",
    )


def collect(expected, observed, start_wall, start_mono):
    try:
        raw, expected_file = read_regular(LOG, MAX_BYTES)
        zone = utc_profile()
        counts = project(raw, expected, observed)
        require(utc_profile() == zone, "clock_unconfirmed")
        check_current_log(expected_file)
        drift = (time.time() - start_wall) - (time.monotonic() - start_mono)
        require(abs(drift) < 1, "clock_unconfirmed")
    except Missing:
        return "source_missing", None, None, None
    except PermissionError:
        return "permission_denied", None, None, None
    except Refused as error:
        return "inconclusive", str(error), None, None
    except OSError:
        return "inconclusive", "read_unconfirmed", None, None
    return "observed", None, counts["refused"], counts["timeout"]


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if sys.platform != "linux" or len(args) != 1 or not args[0].isascii():
        return 2
    expected = args[0].lower()
    if not domain(expected):
        return 2

    def expired(*_args):
        raise Refused("read_unconfirmed")

    signal.signal(signal.SIGALRM, expired)
    wall, monotonic = time.time(), time.monotonic()
    instant = int(wall)
    signal.alarm(4)
    try:
        try:
            drop_privileges()
        except Refused as error:
            result = "inconclusive", str(error), None, None
        except (OSError, KeyError):
            result = "inconclusive", "source_untrusted", None, None
        else:
            result = collect(expected, instant, wall, monotonic)
    except Refused:
        result = "inconclusive", "read_unconfirmed", None, None
    finally:
        signal.alarm(0)
    status, reason, refused, timed_out = result
    receipt = {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "observed_at": datetime.fromtimestamp(instant, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_seconds": WINDOW_SECONDS,
        "matching_refused": refused,
        "matching_timeout": timed_out,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
