"""Local context, syntax and runtime gates for a registered Nginx upstream change."""

import hashlib
import http.client
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from deploy.nginx import config_snapshot as snapshot
from deploy.readonly import nginx_dependencies as parser

if sys.platform == "linux":
    import grp
    import pwd

CONFIG_ROOT = Path("/etc/nginx")
MAIN_CONFIG = CONFIG_ROOT / "nginx.conf"
POLICY_PATH = Path("/etc/opsark/nginx-action.json")
PRIVATE_ROOT = Path("/var/lib/opsark/nginx-action")
NGINX = Path("/usr/sbin/nginx")
BWRAP = Path("/usr/bin/bwrap")
SYSTEMCTL = "/usr/bin/systemctl"
PID_PATH = Path("/run/nginx.pid")
MAX_POLICY = 16_384
MAX_CONTEXT_BYTES = 1_048_576
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_URI = re.compile(r"/[A-Za-z0-9._~/-]{0,127}\Z")
_RELATIVE = re.compile(r"(?:(?:conf\.d|sites-enabled)/[A-Za-z0-9_.-]+\.conf|mime\.types)\Z")
_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.conf\Z")
_MIME = re.compile(r"[a-zA-Z0-9_+.-]+/[a-zA-Z0-9_+.-]+\Z")
_EXT = re.compile(r"[A-Za-z0-9_+-]{1,24}\Z")
_UPSTREAM = re.compile(
    rb"[ \t\r\n]*upstream[ \t]+([a-z][a-z0-9_-]{0,39})[ \t\r\n]*\{[ \t\r\n]*"
    rb"server[ \t]+127\.0\.0\.1:([0-9]{1,5});[ \t\r\n]*\}[ \t\r\n]*\Z"
)


class Refused(ValueError):
    """Only a closed, safe reason may leave the local executor."""


def require(value, reason="policy_refused"):
    if not value:
        raise Refused(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def strict_json(data: bytes):
    def reject(_value):
        raise Refused("policy_refused")

    try:
        return json.loads(
            data.decode("ascii"), object_pairs_hook=snapshot._unique, parse_constant=reject
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("policy_refused") from None


def hex_digest(value) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def valid_port(value) -> bool:
    return type(value) is int and 1 <= value <= 65535


def utc(value: object) -> datetime:
    if type(value) is not str or len(value) > 32:
        raise Refused("policy_refused")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise Refused("policy_refused") from None
    require(result.tzinfo is not None and result.utcoffset() == UTC.utcoffset(result))
    return result.astimezone(UTC)


def clean_uri(value: object) -> bool:
    return (
        type(value) is str
        and _URI.fullmatch(value) is not None
        and "//" not in value
        and not any(part in {".", ".."} for part in value.split("/"))
    )


@dataclass(frozen=True)
class Site:
    site_id: str
    host: str
    listen_port: int
    path: str
    before_sha256: str
    after_sha256: str


@dataclass(frozen=True)
class Policy:
    policy_digest: str
    expires_at: datetime
    target_file: str
    upstream_name: str
    from_port: int
    to_port: int
    nginx_sha256: str
    bwrap_sha256: str
    context_files: tuple[str, ...]
    sites: tuple[Site, ...]

    @property
    def target(self) -> str:
        return "conf.d/" + self.target_file


def parse_policy(raw: bytes) -> Policy:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_POLICY)
    value = strict_json(raw)
    require(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "enabled",
            "expires_at",
            "target_file",
            "upstream_name",
            "from_port",
            "to_port",
            "nginx_sha256",
            "bwrap_sha256",
            "context_files",
            "sites",
        }
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
    )
    require(
        type(value["target_file"]) is str
        and _TARGET.fullmatch(value["target_file"])
        and ".." not in value["target_file"]
        and type(value["upstream_name"]) is str
        and _NAME.fullmatch(value["upstream_name"])
        and valid_port(value["from_port"])
        and valid_port(value["to_port"])
        and value["from_port"] != value["to_port"]
        and hex_digest(value["nginx_sha256"])
        and hex_digest(value["bwrap_sha256"])
    )
    files = value["context_files"]
    require(
        type(files) is list
        and 2 <= len(files) <= 16
        and all(
            type(name) is str and _RELATIVE.fullmatch(name) and ".." not in name for name in files
        )
        and len(set(files)) == len(files)
        and "conf.d/" + value["target_file"] in files
    )
    rows = value["sites"]
    require(type(rows) is list and 2 <= len(rows) <= 8)
    sites = []
    for row in rows:
        require(type(row) is dict and set(row) == set(Site.__dataclass_fields__))
        require(
            type(row["site_id"]) is str
            and _NAME.fullmatch(row["site_id"])
            and type(row["host"]) is str
            and _DOMAIN.fullmatch(row["host"])
            and "." in row["host"]
            and ".." not in row["host"]
            and valid_port(row["listen_port"])
            and clean_uri(row["path"])
            and hex_digest(row["before_sha256"])
            and hex_digest(row["after_sha256"])
        )
        sites.append(Site(**row))
    require(
        len({row.site_id for row in sites}) == len(sites)
        and len({(row.host, row.listen_port) for row in sites}) == len(sites)
        and any(row.before_sha256 == row.after_sha256 for row in sites)
        and any(row.before_sha256 != row.after_sha256 for row in sites)
    )
    return Policy(
        digest(raw),
        utc(value["expires_at"]),
        value["target_file"],
        value["upstream_name"],
        value["from_port"],
        value["to_port"],
        value["nginx_sha256"],
        value["bwrap_sha256"],
        tuple(sorted(files)),
        tuple(sorted(sites, key=lambda row: row.site_id)),
    )


def plain_metadata(parent: int, name: str, identity: dict) -> None:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    try:
        # This release preserves UID/GID and mode. An ACL or other xattr requires a
        # different restore contract, so refuse both the existing and staged inode.
        require(
            not os.listxattr(fd) and snapshot._signature(os.fstat(fd)) == identity,
            "scope_changed",
        )
    finally:
        os.close(fd)


def trusted_read(path: Path, maximum: int, *, private: bool = False, plain: bool = False):
    with snapshot._directory(path.parent, snapshot.DEFAULT_POLICY) as parent:
        raw, identity = snapshot._read(
            parent, path.name, maximum, snapshot.DEFAULT_POLICY, private=private
        )
        if plain:
            plain_metadata(parent, path.name, identity)
        return raw, identity


def active_policy(expected: str) -> Policy:
    raw, _ = trusted_read(POLICY_PATH, MAX_POLICY, private=True)
    policy = parse_policy(raw)
    require(policy.policy_digest == expected, "scope_changed")
    require(datetime.now(UTC) < policy.expires_at, "expired")
    return policy


def candidate_for(raw: bytes, policy: Policy) -> bytes:
    match = _UPSTREAM.fullmatch(raw)
    require(match is not None, "scope_changed")
    assert match is not None  # noqa: S101 - guarded above; narrow Match for static tooling.
    require(
        match[1] == policy.upstream_name.encode("ascii")
        and match[2] == str(policy.from_port).encode("ascii"),
        "scope_changed",
    )
    start, end = match.span(2)
    return raw[:start] + str(policy.to_port).encode("ascii") + raw[end:]


@dataclass(frozen=True)
class Graph:
    files: dict[str, bytes]
    identities: dict[str, dict[str, int]]
    affected_site_ids: tuple[str, ...]

    @property
    def sha256(self) -> str:
        return self.context_sha256()

    def context_sha256(self, *, exclude: str | None = None) -> str:
        return digest(
            canonical(
                {
                    name: {"sha256": digest(raw), "identity": self.identities[name]}
                    for name, raw in sorted(self.files.items())
                    if name != exclude
                }
            )
        )


def _expand(files: dict[str, bytes]):
    seen = {"nginx.conf"}

    def visit(rows, depth):
        require(depth <= 8, "syntax_refused")
        for row in rows:
            if row.name != "include":
                children = (
                    tuple(visit(row.children, depth + 1)) if row.children is not None else None
                )
                yield parser.Directive(row.name, row.args, children, row.path, row.line)
                continue
            require(
                row.children is None
                and len(row.args) == 1
                and row.args[0].startswith("/etc/nginx/"),
                "syntax_refused",
            )
            name = row.args[0][len("/etc/nginx/") :]
            require(name in files and name not in seen, "syntax_refused")
            seen.add(name)
            yield from visit(parser.parse(files[name], name), depth + 1)

    tree = tuple(visit(parser.parse(files["nginx.conf"], "nginx.conf"), 0))
    require(seen == set(files), "syntax_refused")
    return tree


def _leaf(row, values=None):
    require(row.children is None and (values is None or row.args in values), "syntax_refused")


def _numeric(row, maximum=65535):
    _leaf(row)
    require(
        len(row.args) == 1
        and re.fullmatch(r"[1-9][0-9]{0,4}", row.args[0])
        and int(row.args[0]) <= maximum,
        "syntax_refused",
    )


def _location(row):
    require(
        row.children is not None
        and len(row.args) in {1, 2}
        and (len(row.args) == 1 or row.args[0] == "=")
        and clean_uri(row.args[-1]),
        "syntax_refused",
    )
    target = None
    has_response = False
    for child in row.children:
        _leaf(child)
        if child.name == "proxy_pass":
            require(
                not has_response and len(child.args) == 1 and child.args[0].startswith("http://"),
                "syntax_refused",
            )
            name = child.args[0][7:]
            direct = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", name)
            require(
                _NAME.fullmatch(name) or (direct is not None and int(direct[1]) <= 65535),
                "syntax_refused",
            )
            target = name if direct is None else None
            has_response = True
        elif child.name == "return":
            require(
                not has_response
                and len(child.args) == 2
                and child.args[0] == "200"
                and re.fullmatch(r"[ -#%-~]{1,512}", child.args[1]),
                "syntax_refused",
            )
            has_response = True
        elif child.name == "default_type":
            require(len(child.args) == 1 and _MIME.fullmatch(child.args[0]), "syntax_refused")
        elif child.name == "proxy_set_header":
            require(
                child.args in {("Host", "$host"), ("X-Real-IP", "$remote_addr")}, "syntax_refused"
            )
        elif child.name == "proxy_http_version":
            require(child.args in {("1.0",), ("1.1",)}, "syntax_refused")
        else:
            raise Refused("syntax_refused")
    require(has_response, "syntax_refused")
    return len(row.args) == 2, row.args[-1], target


def _server(row):
    require(not row.args and row.children is not None, "syntax_refused")
    port, host, bind, locations = None, None, None, []
    for child in row.children:
        if child.name == "listen":
            _leaf(child)
            require(port is None and len(child.args) == 1, "syntax_refused")
            match = re.fullmatch(r"(?:(127\.0\.0\.1|0\.0\.0\.0):)?([1-9][0-9]{0,4})", child.args[0])
            require(match is not None and int(match[2]) <= 65535, "syntax_refused")
            if match is not None:
                # Normalize existing listen syntax. This function never binds a socket.
                bind, port = match[1] or "0.0.0.0", int(match[2])  # noqa: S104
        elif child.name == "server_name":
            _leaf(child)
            require(
                host is None
                and len(child.args) == 1
                and _DOMAIN.fullmatch(child.args[0])
                and ".." not in child.args[0],
                "syntax_refused",
            )
            host = child.args[0]
        elif child.name == "location":
            locations.append(_location(child))
        else:
            raise Refused("syntax_refused")
    require(
        port is not None
        and host is not None
        and bool(locations)
        and len({item[:2] for item in locations}) == len(locations),
        "syntax_refused",
    )
    return (host, port), bind, locations


def _http(rows, policy: Policy):
    upstreams, servers, binds = {}, {}, {}
    for row in rows:
        if row.name == "upstream":
            require(
                len(row.args) == 1
                and _NAME.fullmatch(row.args[0])
                and row.args[0] not in upstreams
                and row.children is not None
                and len(row.children) == 1,
                "syntax_refused",
            )
            server = row.children[0]
            require(
                server.name == "server" and server.children is None and len(server.args) == 1,
                "syntax_refused",
            )
            match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", server.args[0])
            require(match is not None and int(match[1]) <= 65535, "syntax_refused")
            upstreams[row.args[0]] = row.path
        elif row.name == "server":
            key, bind, locations = _server(row)
            require(key not in servers, "syntax_refused")
            require(binds.setdefault(key[1], bind) == bind, "syntax_refused")
            servers[key] = locations
        elif row.name == "types":
            require(not row.args and row.children is not None, "syntax_refused")
            for child in row.children:
                _leaf(child)
                require(
                    _MIME.fullmatch(child.name) and all(_EXT.fullmatch(x) for x in child.args),
                    "syntax_refused",
                )
        elif row.name in {"sendfile", "tcp_nopush", "gzip"}:
            _leaf(row, {("on",), ("off",)})
        elif row.name in {"keepalive_timeout", "types_hash_max_size"}:
            _numeric(row)
        elif row.name == "access_log":
            _leaf(
                row,
                {
                    ("off",),
                    ("/var/log/nginx/access.log",),
                    ("/var/log/nginx/access.log", "combined"),
                },
            )
        elif row.name == "default_type":
            _leaf(row)
            require(len(row.args) == 1 and _MIME.fullmatch(row.args[0]), "syntax_refused")
        else:
            raise Refused("syntax_refused")
    require(
        upstreams.get(policy.upstream_name) == policy.target
        and set(servers) == {(s.host, s.listen_port) for s in policy.sites},
        "scope_changed",
    )
    affected = []
    for site in policy.sites:
        locations = servers[(site.host, site.listen_port)]
        require(
            all(target is None or target in upstreams for _, _, target in locations),
            "syntax_refused",
        )
        exact = [x for x in locations if x[0] and x[1] == site.path]
        prefix = [x for x in locations if not x[0] and site.path.startswith(x[1])]
        require(bool(exact or prefix), "scope_changed")
        chosen = exact[0] if exact else max(prefix, key=lambda x: len(x[1]))
        impacted = any(target == policy.upstream_name for _, _, target in locations)
        require(
            impacted == (site.before_sha256 != site.after_sha256)
            and (not impacted or chosen[2] == policy.upstream_name),
            "scope_changed",
        )
        if impacted:
            affected.append(site.site_id)
    return tuple(affected)


def validate_graph(files: dict[str, bytes], policy: Policy) -> tuple[str, ...]:
    require(
        set(files) == {"nginx.conf", *policy.context_files}
        and sum(map(len, files.values())) <= MAX_CONTEXT_BYTES
        and all(raw.isascii() for raw in files.values()),
        "scope_changed",
    )
    try:
        tree = _expand(files)
    except parser.Refused:
        raise Refused("syntax_refused") from None
    http = None
    seen = set()
    for row in tree:
        require(row.name not in seen, "syntax_refused")
        seen.add(row.name)
        if row.name == "user":
            _leaf(row, {("www-data",), ("www-data", "www-data")})
        elif row.name == "pid":
            _leaf(row, {("/run/nginx.pid",)})
        elif row.name == "error_log":
            _leaf(row)
            require(
                1 <= len(row.args) <= 2
                and row.args[0] in {"stderr", "/var/log/nginx/error.log"}
                and (len(row.args) == 1 or row.args[1] in {"warn", "error", "crit"}),
                "syntax_refused",
            )
        elif row.name == "worker_processes":
            if row.args == ("auto",):
                _leaf(row)
            else:
                _numeric(row, 16)
        elif row.name == "events":
            require(
                not row.args
                and row.children is not None
                and len(row.children) == 1
                and row.children[0].name == "worker_connections",
                "syntax_refused",
            )
            _numeric(row.children[0])
        elif row.name == "http":
            require(not row.args and row.children is not None, "syntax_refused")
            http = row.children
        else:
            raise Refused("syntax_refused")
    require({"user", "pid", "events", "http"} <= seen and http is not None, "syntax_refused")
    return _http(http or (), policy)


def capture_graph(policy: Policy) -> Graph:
    files, identities = {}, {}
    for name in ("nginx.conf", *policy.context_files):
        files[name], identities[name] = trusted_read(
            CONFIG_ROOT / name, snapshot.MAX_CONFIG_BYTES, plain=name == policy.target
        )
    return Graph(files, identities, validate_graph(files, policy))


def same_context(before: Graph, after: Graph, policy: Policy) -> bool:
    return before.affected_site_ids == after.affected_site_ids and all(
        before.files[name] == after.files[name]
        and before.identities[name] == after.identities[name]
        for name in before.files
        if name != policy.target
    )


def _binary(path: Path, expected: str):
    raw, identity = trusted_read(path, 32 * 1024 * 1024)
    require(digest(raw) == expected and identity["mode"] & 0o111, "scope_changed")
    return identity


def _command(argv, timeout=5):
    return subprocess.run(  # noqa: S603 -- callers supply fixed local commands/verified staging.
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=ENV,
        timeout=timeout,
        check=False,
    )


def syntax_check(policy: Policy, graph: Graph, candidate: bytes) -> None:
    files = {**graph.files, policy.target: candidate}
    require(validate_graph(files, policy) == graph.affected_site_ids, "syntax_refused")
    binaries = (_binary(NGINX, policy.nginx_sha256), _binary(BWRAP, policy.bwrap_sha256))
    account = pwd.getpwnam("www-data")
    require(
        (account.pw_uid, account.pw_gid, grp.getgrnam("www-data").gr_gid) == (33, 33, 33),
        "syntax_refused",
    )
    with (
        snapshot._directory(PRIVATE_ROOT, snapshot.DEFAULT_POLICY, private=True),
        TemporaryDirectory(prefix="syntax-", dir=PRIVATE_ROOT) as folder,
    ):
        stage = Path(folder)
        for name, raw in files.items():
            target = stage / "nginx" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (stage / "passwd").write_bytes(b"www-data:x:33:33::/nonexistent:/usr/sbin/nologin\n")
        (stage / "group").write_bytes(b"www-data:x:33:\n")
        # nginx -t can create temporary directories, chown them and bind listeners.
        # These capabilities apply only inside the private mounts/network namespace.
        args = [
            str(BWRAP),
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CAP_CHOWN",
            "--cap-add",
            "CAP_NET_BIND_SERVICE",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--ro-bind",
            str(stage / "nginx"),
            "/etc/nginx",
            "--ro-bind",
            str(stage / "passwd"),
            "/etc/passwd",
            "--ro-bind",
            str(stage / "group"),
            "/etc/group",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/run",
            "--dir",
            "/run/lock",
            "--tmpfs",
            "/tmp",  # noqa: S108 - sandbox destination, never a host file path.
            "--dir",
            "/var",
            "--dir",
            "/var/log",
            "--dir",
            "/var/lib",
            "--tmpfs",
            "/var/log/nginx",
            "--tmpfs",
            "/var/lib/nginx",
            "--symlink",
            "../run/lock",
            "/var/lock",
            "--chdir",
            "/",
            "--",
            str(NGINX),
            "-t",
            "-q",
            "-e",
            "stderr",
            "-c",
            str(MAIN_CONFIG),
            "-g",
            "daemon on; master_process on;",
        ]
        try:
            process = subprocess.run(  # noqa: S603 - closed sandbox argv and root-owned inputs.
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=ENV,
                timeout=8,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise Refused("syntax_refused") from None
        require(process.returncode == 0, "syntax_refused")
    require(
        binaries == (_binary(NGINX, policy.nginx_sha256), _binary(BWRAP, policy.bwrap_sha256)),
        "scope_changed",
    )


def _bounded_proc(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit, "scope_changed")
    return data


def _master_listens(proc: Path, ports: set[int]) -> None:
    # A localhost response counts only if the pinned Nginx master owns the
    # listening socket and shares this executor's network namespace.
    net = (proc / "ns/net").stat()
    local = Path("/proc/self/ns/net").stat()
    require((net.st_dev, net.st_ino) == (local.st_dev, local.st_ino), "scope_changed")
    sockets = set()
    for index, fd in enumerate((proc / "fd").iterdir()):
        require(index < 2048, "scope_changed")
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        socket = re.fullmatch(r"socket:\[([1-9][0-9]{0,19})\]", link)
        if socket is not None:
            sockets.add(socket[1].encode("ascii"))
    owned = set()
    for line in _bounded_proc(proc / "net/tcp", 1_048_576).splitlines()[1:]:
        fields = line.split()
        if len(fields) > 9 and fields[3] == b"0A" and fields[9] in sockets:
            match = re.fullmatch(rb"(?:00000000|0100007F):([0-9A-F]{4})", fields[1])
            if match is not None:
                owned.add(int(match[1], 16))
    require(ports <= owned, "scope_changed")


def _master_identity(policy: Policy, graph: Graph):
    result = _command(
        [
            SYSTEMCTL,
            "show",
            "--property=MainPID,ControlGroup,ActiveState,LoadState",
            "nginx.service",
        ]
    )
    require(result.returncode == 0 and len(result.stdout) <= 1024, "scope_changed")
    pairs = [line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()]
    require(len(pairs) == 4 and all(len(pair) == 2 for pair in pairs), "scope_changed")
    values = dict(pairs)
    require(
        set(values) == {"MainPID", "ControlGroup", "ActiveState", "LoadState"}
        and values["ActiveState"] == "active"
        and values["LoadState"] == "loaded"
        and values["ControlGroup"] == "/system.slice/nginx.service"
        and re.fullmatch(r"[1-9][0-9]{0,9}", values["MainPID"]),
        "scope_changed",
    )
    pid = int(values["MainPID"])
    return pid, inspect_master(policy, graph, pid).sha256


@dataclass(frozen=True)
class ProcessIdentity:
    birth_tick: int
    sha256: str


def inspect_master(policy: Policy, graph: Graph, pid: int) -> ProcessIdentity:
    require(type(pid) is int and 1 < pid < 2**31, "scope_changed")
    raw_pid, _ = trusted_read(PID_PATH, 32)
    require(raw_pid.strip() == str(pid).encode("ascii"), "scope_changed")
    proc = Path("/proc") / str(pid)
    command = _bounded_proc(proc / "cmdline", 512).rstrip(b"\0")
    require(
        command
        in {
            b"/usr/sbin/nginx\0-c\0/etc/nginx/nginx.conf\0-g\0daemon on; master_process on;",
            b"nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf"
            b" -g daemon on; master_process on;",
        },
        "scope_changed",
    )
    status = _bounded_proc(proc / "status", 8192).splitlines()
    require(
        [line.split() for line in status if line.startswith(b"Uid:")]
        == [[b"Uid:", b"0", b"0", b"0", b"0"]],
        "scope_changed",
    )
    require(
        _bounded_proc(proc / "cgroup", 512).strip() == b"0::/system.slice/nginx.service",
        "scope_changed",
    )
    binary = _binary(NGINX, policy.nginx_sha256)
    require(snapshot._signature((proc / "exe").stat()) == binary, "scope_changed")
    _master_listens(proc, {site.listen_port for site in policy.sites})
    for name, identity in graph.identities.items():
        observed = (proc / "root/etc/nginx" / name).stat()
        require(
            snapshot._signature(observed) == identity and stat.S_ISREG(observed.st_mode),
            "scope_changed",
        )
    start = _bounded_proc(proc / "stat", 8192).rsplit(b") ", 1)[-1].split()
    require(
        len(start) > 19 and start[19].isdigit() and start[0] not in {b"Z", b"X"}, "scope_changed"
    )
    boot = _bounded_proc(Path("/proc/sys/kernel/random/boot_id"), 64).strip()
    require(re.fullmatch(rb"[a-f0-9-]{36}", boot), "scope_changed")
    return ProcessIdentity(
        int(start[19]),
        digest(
            canonical(
                {
                    "boot": boot.decode("ascii"),
                    "start": start[19].decode("ascii"),
                    "pid": pid,
                    "binary": binary,
                }
            )
        ),
    )


@dataclass(frozen=True)
class Master:
    pid: int
    fd: int
    sha256: str

    def verify(self, policy: Policy, graph: Graph) -> None:
        require(_master_identity(policy, graph) == (self.pid, self.sha256), "scope_changed")
        signal.pidfd_send_signal(self.fd, 0)

    def reload(self) -> None:
        signal.pidfd_send_signal(self.fd, signal.SIGHUP)


@contextmanager
def pin_master(policy: Policy, graph: Graph) -> Generator[Master]:
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "scope_changed")
    pid, identity = _master_identity(policy, graph)
    descriptor = os.pidfd_open(pid)
    try:
        bound = Master(pid, descriptor, identity)
        bound.verify(policy, graph)
        yield bound
    finally:
        os.close(descriptor)


def probe(policy: Policy, *, candidate: bool, seconds: float = 5) -> bool:
    deadline = time.monotonic() + seconds
    for site in policy.sites:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        connection = http.client.HTTPConnection(
            "127.0.0.1", site.listen_port, timeout=min(1, remaining)
        )
        try:
            connection.request("GET", site.path, headers={"Host": site.host, "Connection": "close"})
            response = connection.getresponse()
            if response.status != 200:
                return False
            body = response.read(65_537)
            expected = site.after_sha256 if candidate else site.before_sha256
            if len(body) > 65_536 or digest(body) != expected or time.monotonic() > deadline:
                return False
        except (OSError, ValueError, http.client.HTTPException):
            return False
        finally:
            connection.close()
    return True
