#!/usr/bin/python3 -I
"""Project bounded disk Nginx relationships locally; never emit configuration text."""

from __future__ import annotations

import glob
import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypedDict, cast

SCOPE = Path("/etc/opsark/nginx-dependency-scope.json")
MAX_FILES = 32
MAX_BYTES = 131072
MAX_OUTPUT = 14000
UNSUPPORTED_ROUTING = {
    "if",
    "rewrite",
    "return",
    "try_files",
    "set",
    "error_page",
    "auth_request",
    "mirror",
}
PATH = re.compile(r"/etc/nginx/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
SENSITIVE = re.compile(
    r"(?i)-----BEGIN [^\r\n-]{0,80}PRIVATE KEY-----|"
    r"\b(?:authorization|proxy-authorization|cookie|set-cookie)\b|"
    r"\b(?:api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\s*[:= ]|"
    r"\b(?:sk[-_][A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16})\b|"
    r"SQLite format 3|PGDMP|\bCREATE\s+TABLE\b|\b(?:INSERT|REPLACE)\s+INTO\b|"
    r"\bSELECT\s+[^;]{1,500}\bFROM\b|\bCOPY\s+[^;]{1,500}\bFROM\s+STDIN"
)


class Refused(ValueError):
    """Only a closed reason is returned; input values never enter exceptions."""


class ListenAddress(TypedDict):
    ip: str
    port: int


def need(ok, code="configuration_unavailable"):
    if not ok:
        raise Refused(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        d = {}
        for key, value in rows:
            need(key not in d, "scope_invalid")
            d[key] = value
        return d

    def constant(_):
        raise Refused("scope_invalid")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("scope_invalid") from None


def checked_scope(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "scope_invalid")
    value = strict(raw)
    need(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "entry",
            "include_files",
            "include_roots",
            "symlink_roots",
            "compose_project",
        },
        "scope_invalid",
    )
    need(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and type(value["compose_project"]) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value["compose_project"]),
        "scope_invalid",
    )
    for key, limit in (("include_files", 8), ("include_roots", 4), ("symlink_roots", 2)):
        need(
            type(value[key]) is list
            and len(value[key]) <= limit
            and all(type(item) is str for item in value[key])
            and len(set(value[key])) == len(value[key]),
            "scope_invalid",
        )
    for path in [
        value["entry"],
        *value["include_files"],
        *value["include_roots"],
        *value["symlink_roots"],
    ]:
        need(
            type(path) is str
            and PATH.fullmatch(path)
            and all(p not in {".", ".."} for p in PurePosixPath(path).parts),
            "scope_invalid",
        )
    for path in [value["entry"], *value["include_files"]]:
        need(path.endswith(".conf") or path == "/etc/nginx/mime.types", "scope_invalid")
    need(value["entry"] not in value["include_files"], "scope_invalid")
    return value


@dataclass(frozen=True)
class Token:
    value: str
    line: int
    separator: bool = False


@dataclass(frozen=True)
class Directive:
    name: str
    args: tuple[str, ...]
    children: tuple[Directive, ...] | None
    path: str
    line: int


def parse(raw, path):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, "configuration_limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Refused("configuration_invalid") from None
    need(not SENSITIVE.search(text), "content_blocked")
    need(not any(ord(c) < 32 and c not in "\t\r\n" for c in text), "configuration_invalid")
    tokens, word, quote, line, start, i = [], [], None, 1, 1, 0
    started = False
    while i < len(text):
        c = text[i]
        if c == "\\":
            need(i + 1 < len(text), "configuration_invalid")
            i += 1
            # Escapes can change directive semantics; refuse instead of guessing.
            raise Refused("configuration_unsupported")
        if quote:
            if c == quote:
                quote = None
            else:
                word.append(c)
                line += c == "\n"
        elif c in "\"'":
            quote = c
            if not started:
                start = line
            started = True
        elif c == "#":
            # Comments never become tokens, but were included in the privacy gate.
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        elif c.isspace() or c in "{};":
            if started:
                tokens.append(Token("".join(word), start))
                word = []
                started = False
            if c in "{};":
                tokens.append(Token(c, line, True))
            line += c == "\n"
        else:
            if not started:
                start = line
            started = True
            word.append(c)
        need(len(word) <= 1024 and len(tokens) <= 12000, "configuration_limit")
        i += 1
    need(not quote and not started, "configuration_invalid")
    index = 0

    def block(depth, nested):
        nonlocal index
        need(depth <= 16, "configuration_limit")
        rows = []
        while index < len(tokens):
            first = tokens[index]
            if first.separator and first.value == "}":
                need(nested, "configuration_invalid")
                index += 1
                return tuple(rows)
            args = []
            while index < len(tokens) and not tokens[index].separator:
                args.append(tokens[index].value)
                index += 1
            need(
                args and index < len(tokens) and tokens[index].value != "}", "configuration_invalid"
            )
            delimiter = tokens[index].value
            index += 1
            children = block(depth + 1, True) if delimiter == "{" else None
            rows.append(Directive(args[0], tuple(args[1:]), children, path, first.line))
        need(not nested, "configuration_invalid")
        return tuple(rows)

    return block(0, False)


def allowed(path, scope):
    if path in (scope["entry"], *scope["include_files"]):
        return True
    return (path.endswith(".conf") or PurePosixPath(path).name in {"*", "default"}) and any(
        PurePosixPath(path).is_relative_to(root) for root in scope["include_roots"]
    )


def endpoint(value, *, url=False):
    if url:
        match = re.fullmatch(
            r"https?://(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]{1,5})(?:/[A-Za-z0-9._~/-]*)?", value
        )
    else:
        match = re.fullmatch(r"(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]{1,5})", value)
    if not match:
        return None
    try:
        ip = ipaddress.ip_address(match[1].strip("[]"))
    except ValueError:
        return None
    port = int(match[2])
    return {"ip": str(ip), "port": port} if ip.is_loopback and 1 <= port <= 65535 else None


def project(scope_raw, read_file, expand):
    """Pure projection over bounded trusted reader/expander, also used by Fake tests."""
    scope = checked_scope(scope_raw)
    files, stack, count = {}, set(), 0

    def scan(path, depth):
        nonlocal count
        need(depth <= 8 and path not in stack and allowed(path, scope), "include_unavailable")
        need(path not in files, "include_ambiguous")
        need(len(files) < MAX_FILES, "configuration_limit")
        raw = read_file(path)
        count += len(raw)
        need(count <= MAX_BYTES, "configuration_limit")
        files[path] = digest(raw)
        stack.add(path)

        def resolve(rows):
            result = []
            for node in rows:
                if node.name == "include":
                    need(node.children is None and len(node.args) == 1, "include_unavailable")
                    pattern = node.args[0]
                    need(
                        pattern.startswith("/etc/nginx/")
                        and not any(p in {".", ".."} for p in PurePosixPath(pattern).parts)
                        and re.fullmatch(r"/etc/nginx/[A-Za-z0-9_./*-]+", pattern),
                        "include_unavailable",
                    )
                    matches = expand(pattern)
                    need(
                        type(matches) is list
                        and len(matches) <= MAX_FILES
                        and matches == sorted(set(cast(list[str], matches))),
                        "include_unavailable",
                    )
                    # Empty globs are allowed; a missing explicit file is not.
                    need(matches or "*" in pattern, "include_unavailable")
                    for included in matches:
                        result.extend(scan(included, depth + 1))
                else:
                    result.append(
                        Directive(
                            node.name,
                            node.args,
                            resolve(node.children) if node.children is not None else None,
                            node.path,
                            node.line,
                        )
                    )
            return tuple(result)

        result = resolve(parse(raw, path))
        stack.remove(path)
        return result

    tree = scan(scope["entry"], 0)
    http = [n for n in tree if n.name == "http" and n.children is not None]
    need(len(http) == 1, "configuration_unsupported")
    upstreams = {}
    for node in http[0].children:
        if node.name == "upstream" and len(node.args) == 1 and node.children is not None:
            members = [
                endpoint(n.args[0])
                for n in node.children
                if n.name == "server" and len(n.args) == 1 and n.children is None
            ]
            valid = len(members) == len(node.children) and members and all(members)
            need(node.args[0] not in upstreams, "configuration_ambiguous")
            upstreams[node.args[0]] = members if valid else None
    servers = []
    for node in http[0].children:
        if node.name != "server" or node.children is None:
            continue
        need(len(servers) < 32, "configuration_limit")
        domains, routes = [], []
        listens: list[ListenAddress] = []
        reasons = set()
        for child in node.children:
            if child.name == "server_name":
                for domain in child.args:
                    domain = domain.lower().rstrip(".")
                    if DOMAIN.fullmatch(domain) and ".." not in domain:
                        domains.append(domain)
                    else:
                        reasons.add("domain_unsupported")
            if child.name == "listen":
                address = child.args[0] if child.args else ""
                m = re.fullmatch(r"(?:([0-9.]+|\[[0-9a-fA-F:]+\]):)?([0-9]{1,5})", address)
                if m and 1 <= int(m[2]) <= 65535:
                    ip = (m[1] or "0.0.0.0").strip("[]")  # noqa: S104 -- observed address, no listener.
                    try:
                        ip = str(ipaddress.ip_address(ip))
                    except ValueError:
                        reasons.add("listen_unsupported")
                    else:
                        listens.append({"ip": ip, "port": int(m[2])})
                else:
                    reasons.add("listen_unsupported")
            if child.name in UNSUPPORTED_ROUTING:
                reasons.add("routing_unsupported")
        if not domains or not listens:
            reasons.add("server_incomplete")
        for child in node.children:
            if child.name != "location" or child.children is None:
                continue
            proxies = [n for n in child.children if n.name == "proxy_pass"]
            if not proxies:
                continue
            supported_location = (
                len(child.args) == 1
                and re.fullmatch(r"/[A-Za-z0-9._~/-]*", child.args[0])
                or len(child.args) == 2
                and child.args[0] in {"=", "^~"}
                and re.fullmatch(r"/[A-Za-z0-9._~/-]*", child.args[1])
            )
            unsupported = not supported_location or any(
                n.children is not None or n.name in UNSUPPORTED_ROUTING for n in child.children
            )
            endpoints = None
            if not unsupported and len(proxies) == 1 and len(proxies[0].args) == 1:
                destination = proxies[0].args[0]
                direct = endpoint(destination, url=True)
                named = re.fullmatch(
                    r"https?://([A-Za-z0-9_-]{1,63})(?:/[A-Za-z0-9._~/-]*)?", destination
                )
                endpoints = [direct] if direct else upstreams.get(named[1]) if named else None
            routes.append(
                {
                    "file": proxies[0].path,
                    "line": proxies[0].line,
                    "endpoints": endpoints or [],
                    "reason": None if endpoints and not reasons else "routing_unsupported",
                }
            )
        servers.append(
            {
                "server_id": digest(canonical([node.path, node.line])),
                "file": node.path,
                "line": node.line,
                "domains": sorted(set(domains)),
                "listens": sorted(listens, key=canonical),
                "routes": routes,
                "reasons": sorted(reasons),
            }
        )
    # Duplicate virtual hosts on the same socket cannot be selected confidently.
    seen = {}
    for server in servers:
        for domain in server["domains"]:
            for listen in cast(list[ListenAddress], server["listens"]):
                key = (domain, listen["ip"], listen["port"])
                seen.setdefault(key, []).append(server)
    for values in seen.values():
        if len(values) > 1:
            for server in values:
                server["reasons"] = sorted(set(server["reasons"]) | {"duplicate_virtual_host"})
                for route in server["routes"]:
                    route["reason"] = "routing_unsupported"
    value = {
        "schema": "opsark-nginx-disk-dependencies/v1",
        "scope_digest": digest(scope_raw),
        "project": scope["compose_project"],
        "disk_configuration": "observed",
        "loaded_generation": "unknown",
        "files": [{"path": p, "sha256": h} for p, h in sorted(files.items())],
        "servers": servers,
        "actions_enabled": False,
    }
    value["snapshot_digest"] = digest(canonical(value))
    need(len(canonical(value)) <= MAX_OUTPUT, "configuration_limit")
    return value


def trusted(path, *, directory=False):
    s = path.lstat()
    need(
        (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
        and s.st_uid == 0
        and not s.st_mode & 0o022
        and (directory or s.st_nlink == 1),
        "path_untrusted",
    )
    return s


def identity(info):
    # atime can legitimately change on read; do not confuse it with content drift.
    return tuple(
        getattr(info, key)
        for key in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def local_projection():
    need(sys.platform == "linux" and os.geteuid() == 0, "scope_unavailable")
    for parent in reversed(SCOPE.parents):
        trusted(parent, directory=True)
    scope_before = trusted(SCOPE)
    fd = os.open(SCOPE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(
            identity(os.fstat(fd)) == identity(scope_before) and os.fstat(fd).st_size <= 4096,
            "scope_invalid",
        )
        scope_raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    scope = checked_scope(scope_raw)
    opened = {}
    memberships = {}

    def read_file(name):
        path = Path(name)
        need(allowed(name, scope), "include_unavailable")
        # Only registered symlink roots may resolve a sites-enabled leaf.
        for parent in reversed(path.parents):
            trusted(parent, directory=True)
        if path.is_symlink():
            need(
                any(path.is_relative_to(root) for root in scope["include_roots"]), "path_untrusted"
            )
            target = path.resolve(strict=True)
            need(
                any(target.is_relative_to(root) for root in scope["symlink_roots"])
                and (target.suffix == ".conf" or target.name == "default"),
                "path_untrusted",
            )
            for parent in reversed(target.parents):
                trusted(parent, directory=True)
            before_link = path.lstat()
        else:
            target, before_link = path, None
        before = trusted(target)
        need(before.st_size <= MAX_BYTES, "configuration_limit")
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            need(identity(os.fstat(fd)) == identity(before), "configuration_changed")
            raw = os.read(fd, MAX_BYTES + 1)
            need(
                identity(os.fstat(fd)) == identity(before) and len(raw) == before.st_size,
                "configuration_changed",
            )
        finally:
            os.close(fd)
        need(
            identity(target.lstat()) == identity(before)
            and (before_link is None or identity(path.lstat()) == identity(before_link)),
            "configuration_changed",
        )
        opened[name] = (target, before, path, before_link)
        return raw

    def members(pattern):
        need(allowed(pattern, scope), "include_unavailable")
        matches = []
        for match in glob.iglob(pattern):
            matches.append(match)
            need(len(matches) <= MAX_FILES, "configuration_limit")
        return sorted(matches)

    def expand(pattern):
        matches = members(pattern)
        memberships[pattern] = matches
        return matches

    result = project(scope_raw, read_file, expand)
    for target, before, path, link in opened.values():
        need(
            identity(target.lstat()) == identity(before)
            and (link is None or identity(path.lstat()) == identity(link)),
            "configuration_changed",
        )
    need(
        all(members(pattern) == matches for pattern, matches in memberships.items()),
        "configuration_changed",
    )
    need(identity(SCOPE.lstat()) == identity(scope_before), "configuration_changed")
    return result


def main():
    def expired(*_):
        raise Refused("collection_timeout")

    try:
        need(len(sys.argv) == 1, "scope_invalid")
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 4)
        result = local_projection()
    except BaseException as error:
        result = {
            "schema": "opsark-nginx-disk-dependencies-error/v1",
            "reason": str(error) if type(error) is Refused else "configuration_unavailable",
            "actions_enabled": False,
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.buffer.write(canonical(result))
    return 0 if result["schema"] == "opsark-nginx-disk-dependencies/v1" else 1


if __name__ == "__main__":
    raise SystemExit(main())
